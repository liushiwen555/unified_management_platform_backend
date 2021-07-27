import json
from abc import ABC, abstractmethod
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import List, Dict, Any

from dateutil import parser
from django.db.models import Count
from django.utils import timezone

from auditor.models import RiskCountry
from log.models import AlertDistribution, DeviceAllAlert, IncrementDistribution
from setting.models import Location
from statistic.serializers import IPMapSerializer, RiskSrcCountrySerializer, \
    AttackStatisticSerializer, DeviceAlertDistributionSerializer, \
    IncrementTrendSerializer, AbnormalIPSerializer, ExternalIPTopSerializer, \
    PortRankSerializer, IPRankSerializer
from utils.helper import safe_divide, send_websocket_message
from utils.ip_search import ip_search, IPRecord
from utils.unified_redis import rs, cache, IPDuplicate, IPRedisQueue

WEBSOCKET_TYPE = 'unified_push'


class _Processor(ABC):
    @abstractmethod
    def set_next(self, processor):
        pass

    @abstractmethod
    def process(self, *args, **kwargs):
        pass

    @abstractmethod
    def save(self, *args, **kwargs):
        pass

    @classmethod
    @abstractmethod
    def clean(cls):
        pass


class Processor(_Processor):
    _next_processor: _Processor = None
    websocket_group = None

    def __init__(self, current: datetime):
        self.current = current

    def get_date(self, current=None) -> str:
        if not current:
            return str(timezone.localtime(self.current).date())
        else:
            return str(timezone.localtime(current).date())

    def set_next(self, processor: _Processor) -> _Processor:
        self._next_processor = processor
        return processor

    @abstractmethod
    def process(self, data: Dict):
        """
        处理协议审计的数据，提取有效信息
        :param data:
        {'id': 1234,
        'src_ip': '192.168.111.186',
        'src_mac': '00:0C:29:45:C6:DC',
         'src_port': 58810,
          'dst_ip': '192.168.111.45',
         'dst_mac': '9C:B6:D0:F0:91:9B',
          'dst_port': 44818,
          'l4_protocol': 1,
         'protocol': 'ENIP',
         'content': '>> Data <<:\n\nInterface Handle: 0x000cf003\nLength: 0\nStatus: No Memory Resources (0x00000002)\nCommand: Send RR Data (0x006f)\nSender Context: 0000b2001a005202\nOptions: 0x01240620\nSession Handle: 0x00020000\nTimeout: 519\nItem Count: 25632',
         'occurred_at': '2020-12-16T11:17:47+08:00'},
        :return:
        """
        if self._next_processor:
            return self._next_processor.process(data)
        return None

    @abstractmethod
    def save(self):
        if self._next_processor:
            return self._next_processor.save()

    @classmethod
    def process_list(cls, current: datetime) -> _Processor:
        processor = TodayExternalIP(current)
        processors = [PreProcess, PortRank, ProtocolIPRank, IPSource,
                      IPQueueProcess, AttackIPRank]

        _processor = processor
        for p in processors:
            _processor = _processor.set_next(p(current))

        return processor

    @classmethod
    def process_alert_list(cls, current: datetime) -> _Processor:
        processor = AlertCategoryDistribution(current)
        processors = [IncrementDistributionProcess]

        _processor = processor
        for p in processors:
            _processor = _processor.set_next(p(current))
        return processor

    @classmethod
    @abstractmethod
    def clean(cls):
        """
        清理历史的redis缓存
        :return:
        """
        pass

    @abstractmethod
    def _local_save(self, *args, **kwargs):
        """
        存储在实例中，而不存储在缓存内
        :return:
        """
        pass

    # @abstractmethod
    def websocket_send(self):
        pass


class TodayExternalIP(Processor):
    key_pattern = 'auditor_external_ip'
    websocket_group = 'assets'

    def __init__(self, current: datetime):
        super().__init__(current)
        self.key = self.key_pattern + self.get_date()
        self._data: Dict[str, int] = {}

    def process(self, data: Dict):
        """
        {'id': 1234, 'src_ip': '123.1.11.1', 'src_mac': '00:0C:29:45:C6:DC',
         'src_port': 58810, 'dst_ip': '192.168.111.45',
         'dst_mac': '9C:B6:D0:F0:91:9B', 'dst_port': 44818, 'l4_protocol': 1,
         'protocol': 'ENIP',
         'content': '>> Data <<:\n\nInterface Handle: 0x000cf003\nLength: 0\nStatus: No Memory Resources (0x00000002)\nCommand: Send RR Data (0x006f)\nSender Context: 0000b2001a005202\nOptions: 0x01240620\nSession Handle: 0x00020000\nTimeout: 519\nItem Count: 25632',
         'occurred_at': '2020-12-16T11:17:47+08:00'}
        :param data:
        :return:
        {'127.1.1.1': xxx, '222.11.111.11': xxx},
        """
        if data['src_ip']:
            if ':' in data['src_ip']:
                src_ip = IPv6Address(data['src_ip'])
            else:
                src_ip = IPv4Address(data['src_ip'])
            if src_ip.is_global:
                self._local_save(data['src_ip'])
        if data['dst_ip']:
            if ':' in data['dst_ip']:
                dst_ip = IPv6Address(data['dst_ip'])
            else:
                dst_ip = IPv4Address(data['dst_ip'])
            if dst_ip.is_global:
                self._local_save(data['dst_ip'])
        super().process(data)

    def save(self):
        for ip, count in self._data.items():
            self.set_ip(ip, count)
        self.websocket_send()
        super().save()

    def websocket_send(self):
        data = self.get_top_n()
        serializer = ExternalIPTopSerializer(data)
        message = {
            'message': self.websocket_group,
            'data': {
                'external_ip_top_five': serializer.data,
            }
        }
        send_websocket_message(self.websocket_group, message, WEBSOCKET_TYPE)

    def _local_save(self, ip: str):
        """
        存储到_data内，不存到缓存内
        :return:
        """
        if ip in self._data:
            self._data[ip] += 1
        else:
            self._data[ip] = 1

    def set_ip(self, ip: str, count: int = 1):
        rs.zincrby(self.key, count, ip)

    def get_top_n(self, n: int = 5) -> List[Dict]:
        """
        :param n: 前n个
        :return: [{'ip': xxx, 'total': xxx}]
        """
        data = rs.zrevrange(self.key, 0, n - 1, withscores=True)
        result = []
        for i in data:
            result.append({'ip': i[0].decode('utf-8'), 'count': int(i[1])})
        return result

    @classmethod
    def clean(cls):
        keys = rs.keys(cls.key_pattern + '*')
        for key in keys:
            rs.delete(key)


class PortRank(Processor):
    src_port_key_pattern = 'auditor_src_port'
    dst_port_key_pattern = 'auditor_dst_port'
    src_total_key_pattern = 'auditor_src_total'
    dst_total_key_pattern = 'auditor_dst_total'
    websocket_group = 'network'

    def __init__(self, current: datetime):
        super(PortRank, self).__init__(current)
        self.src_key = self.src_port_key_pattern + self.get_date()
        self.dst_key = self.dst_port_key_pattern + self.get_date()
        self.src_total_key = self.src_total_key_pattern + self.get_date()
        self.dst_total_key = self.dst_total_key_pattern + self.get_date()
        self._data: Dict[str, Dict[int, int]] = {
            'src_port': {}, 'dst_port': {},
        }

    def process(self, data: Dict):
        src_port = data.get('src_port')
        if src_port:
            self._local_save('src_port', src_port)
        dst_port = data.get('dst_port')
        if dst_port:
            self._local_save('dst_port', dst_port)
        super().process(data)

    def save(self):
        src_total = 0
        src_ports = self._data['src_port']
        for p, count in src_ports.items():
            self.set_src_port(p, count)
            src_total += count
        # 更新今日的端口出现总数
        cache.incr(self.src_total_key, src_total)

        dst_total = 0
        dst_ports = self._data['dst_port']
        for p, count in dst_ports.items():
            self.set_dst_port(p, count)
            dst_total += count
        cache.incr(self.dst_total_key, dst_total)
        self.websocket_send()
        super().save()

    def websocket_send(self):
        message = {
            'message': self.websocket_group,
            'data': {
                'port_top_five': PortRankSerializer(self.get_top_n()).data,
            }
        }
        send_websocket_message(self.websocket_group, message, WEBSOCKET_TYPE)

    def _local_save(self, port_type: str, port: int):
        """
        :param port_type: src_port or dst_port
        :param
        :return:
        {
          {'src_port': {'112': xx},
          {'dst_port': {'222': xx},
        }
        """
        if port in self._data[port_type]:
            self._data[port_type][port] += 1
        else:
            self._data[port_type][port] = 1

    @classmethod
    def clean(cls):
        src_keys = rs.keys(cls.src_port_key_pattern + '*')
        dst_keys = rs.keys(cls.dst_port_key_pattern + '*')
        src_total_keys = rs.keys(cls.src_total_key_pattern + '*')
        dst_total_keys = rs.keys(cls.dst_total_key_pattern + '*')
        keys = src_keys + dst_keys + src_total_keys + dst_total_keys
        for k in keys:
            cache.delete(k)

    def set_src_port(self, port: int, count: int = 1):
        cache.zincrby(self.src_key, count, port)

    def set_dst_port(self, port: int, count: int = 1):
        cache.zincrby(self.dst_key, count, port)

    def get_top_n_src_port(self, n: int = 5) -> List[Dict]:
        """
        :param n: 前n个源端口
        :return: [{'port': xxx, 'total': xxx}]
        """
        data = cache.zrevrange(self.src_key, 0, n - 1, withscores=True)
        total = int(cache.get(self.src_total_key) or 0)
        result = []
        for i in data:
            count = int(i[1])
            total -= count
            result.append({'port': i[0], 'count': count})
        result.append({'port': '其他', 'count': total})
        return result

    def get_top_n_dst_port(self, n: int = 5) -> List[Dict]:
        """
        :param n: 前n个目的端口
        :return: [{'port': xxx, 'total': xxx}]
        """
        data = cache.zrevrange(self.dst_key, 0, n - 1, withscores=True)
        total = int(cache.get(self.dst_total_key) or 0)
        result = []
        for i in data:
            count = int(i[1])
            total -= count
            result.append({'port': i[0], 'count': count})
        result.append({'port': '其他', 'count': total})
        return result

    def get_top_n(self, n: int = 5) -> Dict[str, Any]:
        """
        :param n:
        :return:
        {
            'src_port': [{'port': xxx, 'count': xxx}, ...]
            'dst_port': [{'port': xxx, 'count': xxx}, ...]
        }
        """
        src = self.get_top_n_src_port(n)
        dst = self.get_top_n_dst_port(n)

        return {'src_port': src, 'dst_port': dst}


class ProtocolIPRank(Processor):
    """
    协议审计，流量源TOP5和目的TOP5
    """
    src_ip_pattern = 'auditor_src_ip'
    dst_ip_pattern = 'auditor_dst_ip'
    websocket_group = 'network'

    def __init__(self, current: datetime):
        super().__init__(current)
        self.src_key = self.src_ip_pattern + self.get_date()
        self.dst_key = self.dst_ip_pattern + self.get_date()
        self._data: Dict[str, Dict[str, int]] = {
            'src_ip': {}, 'dst_ip': {},
        }

    def process(self, data: Dict):
        """
        {'id': 1234, 'src_ip': '123.1.11.1', 'src_mac': '00:0C:29:45:C6:DC',
         'src_port': 58810, 'dst_ip': '192.168.111.45',
         'dst_mac': '9C:B6:D0:F0:91:9B', 'dst_port': 44818, 'l4_protocol': 1,
         'protocol': 'ENIP',
         'content': '>> Data <<:\n\nInterface Handle: 0x000cf003\nLength: 0\nStatus: No Memory Resources (0x00000002)\nCommand: Send RR Data (0x006f)\nSender Context: 0000b2001a005202\nOptions: 0x01240620\nSession Handle: 0x00020000\nTimeout: 519\nItem Count: 25632',
         'occurred_at': '2020-12-16T11:17:47+08:00'}
        :param data:
        :return:
        """
        self._local_save('src_ip', data['src_ip'])
        self._local_save('dst_ip', data['dst_ip'])
        super().process(data)

    def save(self):
        src_ips = self._data['src_ip']
        for ip, count in src_ips.items():
            self.set_src_ip(ip, count)
        dst_ips = self._data['dst_ip']
        for ip, count in dst_ips.items():
            self.set_dst_ip(ip, count)
        self.websocket_send()
        super().save()

    def websocket_send(self):
        message = {
            'message': self.websocket_group,
            'data': {
                'ip_top_five': IPRankSerializer(self.get_top_n()).data
            }
        }
        send_websocket_message(self.websocket_group, message, WEBSOCKET_TYPE)

    @classmethod
    def clean(cls):
        src_keys = rs.keys(cls.src_ip_pattern + '*')
        dst_keys = rs.keys(cls.dst_ip_pattern + '*')
        keys = src_keys + dst_keys
        for k in keys:
            cache.delete(k)

    def _local_save(self, ip_type: str, ip: str):
        if not ip:
            return
        data = self._data[ip_type]
        if ip in data:
            data[ip] += 1
        else:
            data[ip] = 1

    def set_src_ip(self, ip: str, count: int = 1):
        cache.zincrby(self.src_key, count, ip)

    def set_dst_ip(self, ip: str, count: int = 1):
        cache.zincrby(self.dst_key, count, ip)

    def get_top_n_src_ip(self, n: int = 5):
        data = cache.zrevrange(self.src_key, 0, n - 1, withscores=True)
        result = []
        if not data:
            return result
        top = int(data[0][1])
        for i in data:
            count = int(i[1])
            percent = safe_divide(count * 100, top)
            result.append({'ip': i[0], 'count': count,
                           'percent': percent})
        return result

    def get_top_n_dst_ip(self, n: int = 5):
        data = cache.zrevrange(self.dst_key, 0, n - 1, withscores=True)
        result = []
        if not data:
            return result
        top = int(data[0][1])
        for i in data:
            count = int(i[1])
            percent = safe_divide(count * 100, top)
            result.append({'ip': i[0], 'count': count,
                           'percent': percent})
        return result

    def get_top_n(self, n: int = 5):
        """
        :param n:
        :return:
        {
            src_ip: [{'ip': xxx, 'count': xxx, 'percent': xxx}],
            dst_ip: [{'ip': xxx, 'count': xxx, 'percent': xxx}],
        }
        """
        src = self.get_top_n_src_ip(n)
        dst = self.get_top_n_dst_ip(n)

        return {'src_ip': src, 'dst_ip': dst}


class MapItem(object):
    def __init__(self, city, src_c, src_p, src_city, src_lat, src_long,
                 dst_c, dst_p, dst_city, dst_lat, dst_long, count):
        self.city = city
        self.src_c = src_c
        self.src_p = src_p
        self.src_city = src_city
        self.src_lat = src_lat
        self.src_long = src_long
        self.dst_c = dst_c
        self.dst_p = dst_p
        self.dst_city = dst_city
        self.dst_lat = dst_lat
        self.dst_long = dst_long
        self.count = count

    def __str__(self):
        return f'{self.city}: {self.count}'

    def __repr__(self):
        return f'{self.city}: {self.count}'


class IPSource(Processor):
    """
    查询IP所属的GPS位置，国家，省份和城市
    """
    chinese = ['China', 'Taiwan (Province of China)', 'Macao', 'Hong Kong']
    city_key_pattern = 'auditor_city_ip'
    country_key_pattern = 'auditor_country_ip'
    attack_key_pattern = 'auditor_attack'
    duplicate_key_pattern = 'auditor_duplicate'
    duplicate_threshold = 100000000
    websocket_group = 'security'

    def __init__(self, current: datetime):
        super().__init__(current)
        self.city_key = self.city_key_pattern + self.get_date()
        self.country_key = self.country_key_pattern + self.get_date()
        self.attack_key = self.attack_key_pattern + self.get_date()
        self._duplicate = IPDuplicate.create_duplicate_ip(current)  # 和历史IP去重
        self._today_duplicate = self.duplicate_key_pattern + self.get_date()
        self._city_data = {}
        self._country_data = {}  # {'中国': 1000}
        self._attack_data = {'count': 0, 'src_ip': 0, 'foreign': 0,
                             'external_ip': 0, 'history_src_ip': 0,
                             'history_foreign': 0}
        location, _ = Location.objects.get_or_create(id=1)
        self.default = IPRecord('', location.country, location.province,
                                location.city, location.latitude,
                                location.longitude)

    def process(self, data: Dict):
        src_ip = data['src_ip']
        if src_ip and not data['src_private']:
            # 外网，境外访问需要记录次数
            if data['src_record']:
                self._attack_save(data['src_record'].country, src_ip)
                self._country_save(data['src_record'].country)
            self._external_ip_save()
            self._attack_ip_save()
        dst_ip = data['dst_ip']
        if dst_ip and not data['dst_private']:
            self._external_ip_save()
        src = data['src_record']
        dst = data['dst_record']
        if src and dst:
            if not (data['src_private'] and data['dst_private']):
                self._local_save(src, dst)
        super().process(data)

    def save(self):
        for city, data in self._city_data.items():
            self.save_city_ip(city, data)

        for c, count in self._country_data.items():
            self.save_country_ip(c, count)
        self.save_attack_data()
        self.websocket_send()
        super().save()

    def websocket_send(self):
        """
        协议审计IP地理信息统计结果推送websocket
        """
        message = {
            'message': self.websocket_group,
            'data': {
                'risk_country_top': RiskSrcCountrySerializer(
                    self.get_country_top_n(5)).data,
                'attack_statistic': AttackStatisticSerializer(
                    self.get_attack_data()).data,
            },
        }
        send_websocket_message(self.websocket_group, message, WEBSOCKET_TYPE)
        ip_map = {
            'message': 'ip_map',
            'data': {
                'ip_map': IPMapSerializer(self.get_city_data()).data,
            }
        }
        send_websocket_message('ip_map', ip_map, WEBSOCKET_TYPE)

    @classmethod
    def clean(cls):
        city_keys = cache.keys(cls.city_key_pattern + '*')
        country_keys = cache.keys(cls.country_key_pattern + '*')
        attack_keys = cache.keys(cls.attack_key_pattern + '*')
        duplicate_keys = cache.keys(cls.duplicate_key_pattern + '*')

        keys = city_keys + country_keys + attack_keys + duplicate_keys
        for k in keys:
            cache.delete(k)

    def _local_save(self, src: IPRecord, dst: IPRecord):
        """
        :param src: country, province, city, latitude, longitude
        :param dst: country, province, city, latitude, longitude
        :return:
        {'city': count}
        {'country': count}
        """
        if not src.country or not dst.country:
            return
        self._city_save(src, dst)

    def _city_save(self, src: IPRecord, dst: IPRecord):
        """
        :param src: country, province, city, latitude, longitude
        :param dst: country, province, city, latitude, longitude
        :return:
        """
        orient = src.city + '->' + dst.city
        if orient in self._city_data:
            self._city_data[orient]['count'] += 1
        else:
            self._city_data[orient] = {
                'src_lat': src.latitude,
                'src_long': src.longitude,
                'dst_lat': dst.latitude,
                'dst_long': dst.longitude,
                'src_c': src.country,
                'src_p': src.province,
                'src_city': src.city,
                'dst_c': dst.country,
                'dst_p': dst.province,
                'dst_city': dst.city,
                'count': 1
            }

    def _country_save(self, country):
        """
        记录外网访问的次数
        :param country: 国家
        :return:
        """
        if not country:
            return
        if country in self._country_data:
            self._country_data[country] += 1
        else:
            self._country_data[country] = 1

    def _attack_save(self, country, ip):
        """
        记录外网访问次数，境外访问次数
        :param ip: 需要使用ip判断去重
        """
        """
        这里只记录一下今天遇到的IP
        如果hyperloglog存储了过多的内容，会删掉当前的hyperloglog，将set里的数据导入hyperloglog
        """
        if cache.sadd(self._today_duplicate, ip):
            # 今日不重复IP
            self._attack_data['src_ip'] += 1
            if country and country != '中国':
                self._attack_data['foreign'] += 1
        if not self._duplicate.is_duplicate_ip(ip):
            self._attack_data['history_src_ip'] += 1
            if country and country != '中国':
                self._attack_data['history_foreign'] += 1

    def _attack_ip_save(self):
        """
        记录外网的源IP次数
        """
        self._attack_data['count'] += 1

    def _external_ip_save(self):
        """
        记录外网的源IP和目的IP次数
        """
        self._attack_data['external_ip'] += 1

    def save_city_ip(self, city, city_data):
        value = cache.hget(self.city_key, city)
        if value and value != b'null':
            value = json.loads(value)
            city_data['count'] += value['count']
        cache.hset(self.city_key, city, json.dumps(city_data))

    def save_country_ip(self, country: str, count=1):
        """
        {'中国'： 100}
        :return:
        """
        try:
            r = RiskCountry.objects.get(country=country)
            r.count = r.count + count
            r.save()
        except RiskCountry.DoesNotExist:
            RiskCountry.objects.create(country=country, count=count)

    def save_attack_data(self):
        cache.hincrby(self.attack_key, 'count', self._attack_data['count'])
        cache.hincrby(self.attack_key, 'src_ip', self._attack_data['src_ip'])
        cache.hincrby(self.attack_key, 'history_src_ip',
                      self._attack_data['history_src_ip'])
        cache.hincrby(self.attack_key, 'foreign', self._attack_data['foreign'])
        cache.hincrby(self.attack_key, 'history_foreign',
                      self._attack_data['history_foreign'])
        cache.hincrby(self.attack_key, 'external_ip',
                      self._attack_data['external_ip'])

    def get_city_data(self) -> List[MapItem]:
        data = cache.hgetall(self.city_key)
        result = []
        for city, city_data in data.items():
            d = {'city': city}
            d.update(json.loads(city_data))
            result.append(MapItem(**d))
        return result

    def get_country_top_n(self, n=5) -> List[RiskCountry]:
        data = RiskCountry.objects.order_by('-count')[:n]
        return data

    def get_attack_data(self):
        data = cache.hgetall(self.attack_key)
        result = {'count': 0, 'src_ip': 0, 'foreign': 0, 'external_ip': 0,
                  'history_src_ip': 0, 'history_foreign': 0}
        for key in result.keys():
            result[key] = int(data.get(key, 0))
        return result


class AlertCategoryDistribution(Processor):
    """
    统计安全威胁分布累计值
    分安全威胁5个类别统计
    除了第一次统计所有值以外，都统计累加值加到原来的值上
    """
    distribution = None
    websocket_group = 'security'

    def process(self, data: Dict):
        super().process(data)

    def save(self):
        distribution = AlertDistribution.objects.first()
        if distribution:
            data = self.get_distribution(distribution.update_time)
            distribution.scan += data.get(DeviceAllAlert.CATEGORY_SCAN, 0)
            distribution.flaw += data.get(DeviceAllAlert.CATEGORY_FLAW, 0)
            distribution.penetration += data.get(
                DeviceAllAlert.CATEGORY_PENETRATION, 0)
            distribution.apt += data.get(DeviceAllAlert.CATEGORY_APT, 0)
            distribution.other += data.get(DeviceAllAlert.CATEGORY_OTHER, 0)
            distribution.update_time = self.current
            distribution.save()
        else:
            data = self.get_distribution()
            distribution = AlertDistribution.objects.create(
                scan=data.get(DeviceAllAlert.CATEGORY_SCAN, 0),
                flaw=data.get(DeviceAllAlert.CATEGORY_FLAW, 0),
                penetration=data.get(DeviceAllAlert.CATEGORY_PENETRATION, 0),
                apt=data.get(DeviceAllAlert.CATEGORY_APT, 0),
                other=data.get(DeviceAllAlert.CATEGORY_OTHER, 0),
                update_time=self.current
            )
        self.distribution = distribution
        self.websocket_send()
        super().save()

    @classmethod
    def clean(cls):
        pass

    def _local_save(self):
        pass

    def get_distribution(self, update_time: datetime = None) -> Dict[int, int]:
        queryset = DeviceAllAlert.objects.filter(occurred_time__lt=self.current)
        if update_time:
            queryset = queryset.filter(occurred_time__gte=update_time)
        data = queryset.values('category').annotate(count=Count('id')).order_by(
            'category')
        result = {i['category']: i['count'] for i in data}
        return result

    def websocket_send(self):
        """
        推送安全威胁分布
        """
        message = {
            'message': self.websocket_group,
            'data': {
                'device_alert_distribution': DeviceAlertDistributionSerializer(
                    self.distribution).data,
            }
        }

        send_websocket_message(self.websocket_group, message, WEBSOCKET_TYPE)


class IncrementDistributionProcess(Processor):
    """
    统计每次同步的增量，按照威胁类别区分
    """
    websocket_group = 'security'

    def __init__(self, current: datetime):
        super().__init__(current)
        self._data = {}

    def process(self, data: Dict):
        category = data['category']
        self._local_save(category)

    def save(self):
        IncrementDistribution.objects.create(
            scan=self._data.get(DeviceAllAlert.CATEGORY_SCAN, 0),
            flaw=self._data.get(DeviceAllAlert.CATEGORY_FLAW, 0),
            penetration=self._data.get(DeviceAllAlert.CATEGORY_PENETRATION, 0),
            apt=self._data.get(DeviceAllAlert.CATEGORY_APT, 0),
            other=self._data.get(DeviceAllAlert.CATEGORY_OTHER, 0),
            update_time=self.current
        )
        self.websocket_send()
        super().save()

    @classmethod
    def clean(cls):
        pass

    def _local_save(self, category: int):
        if category in self._data:
            self._data[category] += 1
        else:
            self._data[category] = 1

    def websocket_send(self):
        """
        推送每次同步的安全威胁新增数量
        """
        message = {
            'message': self.websocket_group,
            'data': {
                'alert_trend': IncrementTrendSerializer(
                    IncrementDistribution.objects.order_by('-update_time')[
                    :48]).data
            }
        }
        send_websocket_message(self.websocket_group, message, WEBSOCKET_TYPE)


class IPQueueProcess(Processor):
    """
    使用队列记录外网IP和境外访问IP的数据
    """
    external_key = 'external_ip_queue'
    foreign_key = 'foreign_ip_queue'
    websocket_group = 'abnormal'

    def __init__(self, current: datetime):
        super().__init__(current)
        self._external_queue = []
        self._foreign_queue = []

    def process(self, data: Dict):
        src_ip = data['src_ip']
        update_time = parser.parse(data['occurred_at'])
        if src_ip:
            if data['src_ipv6']:
                if not data['src_private']:
                    src_record = IPRecord(src_ip)
                    self._external_ip_save(src_record, update_time)
            else:
                if not data['src_private']:
                    src_record = data['src_record']
                    if not src_record:
                        src_record = ip_search.search_ip_location(src_ip)
                    self._external_ip_save(src_record, update_time)
                    if src_record.country != '中国':
                        self._foreign_ip_save(src_record, update_time)
        super().process(data)

    def save(self):
        external_queue = IPRedisQueue(self.external_key, 5)
        foreign_queue = IPRedisQueue(self.foreign_key, 5)
        external_data = external_queue.data + self._external_queue
        external_data = sorted(external_data, key=lambda i: i['update_time'],
                               reverse=True)
        foreign_data = foreign_queue.data + self._foreign_queue
        foreign_data = sorted(foreign_data, key=lambda i: i['update_time'],
                              reverse=True)

        external_queue.set(external_data[:5])
        foreign_queue.set(foreign_data[:5])
        self.websocket_send()
        super().save()

    @classmethod
    def clean(cls):
        cache.delete(cls.external_key)
        cache.delete(cls.foreign_key)

    def _local_save(self, *args, **kwargs):
        pass

    def _external_ip_save(self, record: IPRecord, update_time: datetime):
        if record and len(self._external_queue) <= 5:
            self._external_queue.append({
                'ip': record.ip, 'country': record.country,
                'province': record.province, 'city': record.city,
                'update_time': update_time,
            })

    def _foreign_ip_save(self, record: IPRecord, update_time: datetime):
        if record and len(self._foreign_queue) <= 5:
            self._foreign_queue.append({
                'ip': record.ip, 'country': record.country,
                'province': record.province, 'city': record.city,
                'update_time': update_time,
            })

    def get_external_ip(self):
        return IPRedisQueue(self.external_key, 5).data

    def get_foreign_ip(self):
        return IPRedisQueue(self.foreign_key, 5).data

    def websocket_send(self):
        external_ip = AbnormalIPSerializer(data=self.get_external_ip(),
                                           many=True)
        external_ip.is_valid(raise_exception=True)
        foreign_ip = AbnormalIPSerializer(data=self.get_foreign_ip(),
                                          many=True)
        foreign_ip.is_valid(raise_exception=True)
        message = {
            'message': self.websocket_group,
            'data': {
                'external_ip': external_ip.data,
                'foreign_ip': foreign_ip.data,
            }
        }
        send_websocket_message(self.websocket_group, message, WEBSOCKET_TYPE)


class AttackIPRank(Processor):
    """
    协议审计，统计外网访问内网的情况下的攻击源IP和被攻击IP
    """
    src_ip_pattern = 'auditor_attack_src_ip'
    dst_ip_pattern = 'auditor_attack_dst_ip'
    websocket_group = 'attack'

    def __init__(self, current: datetime):
        super().__init__(current)
        self.src_key = self.src_ip_pattern + self.get_date()
        self.dst_key = self.dst_ip_pattern + self.get_date()
        self._data: Dict[str, Dict[str, int]] = {
            'src_ip': {}, 'dst_ip': {},
        }

    def process(self, data: Dict):
        """
        :param data:
        :return:
        """
        if data['src_ip'] and data['dst_ip']:
            # 外网访问内网的情况下需要记录
            if not data['src_private'] and data['dst_private']:
                self._local_save('src_ip', data['src_ip'])
                self._local_save('dst_ip', data['dst_ip'])
        super().process(data)

    def save(self):
        src_ips = self._data['src_ip']
        for ip, count in src_ips.items():
            self.set_src_ip(ip, count)
        dst_ips = self._data['dst_ip']
        for ip, count in dst_ips.items():
            self.set_dst_ip(ip, count)
        self.websocket_send()
        super().save()

    @classmethod
    def clean(cls):
        src_keys = rs.keys(cls.src_ip_pattern + '*')
        dst_keys = rs.keys(cls.dst_ip_pattern + '*')
        keys = src_keys + dst_keys
        for k in keys:
            cache.delete(k)

    def _local_save(self, ip_type: str, ip: str):
        if not ip:
            return
        data = self._data[ip_type]
        if ip in data:
            data[ip] += 1
        else:
            data[ip] = 1

    def set_src_ip(self, ip: str, count: int = 1):
        cache.zincrby(self.src_key, count, ip)

    def set_dst_ip(self, ip: str, count: int = 1):
        cache.zincrby(self.dst_key, count, ip)

    def get_top_n_src_ip(self, n: int = 5):
        data = cache.zrevrange(self.src_key, 0, n - 1, withscores=True)
        result = []
        if not data:
            return result
        top = int(data[0][1])
        for i in data:
            count = int(i[1])
            percent = safe_divide(count * 100, top)
            result.append({'ip': i[0], 'count': count,
                           'percent': percent})
        return result

    def get_top_n_dst_ip(self, n: int = 5):
        data = cache.zrevrange(self.dst_key, 0, n - 1, withscores=True)
        result = []
        if not data:
            return result
        top = int(data[0][1])
        for i in data:
            count = int(i[1])
            percent = safe_divide(count * 100, top)
            result.append({'ip': i[0], 'count': count,
                           'percent': percent})
        return result

    def get_top_n(self, n: int = 5):
        """
        :param n:
        :return:
        {
            src_ip: [{'ip': xxx, 'count': xxx, 'percent': xxx}],
            dst_ip: [{'ip': xxx, 'count': xxx, 'percent': xxx}],
        }
        """
        src = self.get_top_n_src_ip(n)
        dst = self.get_top_n_dst_ip(n)

        return {'src_ip': src, 'dst_ip': dst}

    def websocket_send(self):
        message = {
            'message': self.websocket_group,
            'data': {
                'attack_ip_rank': self.get_top_n(),
            }
        }
        send_websocket_message(self.websocket_group, message, WEBSOCKET_TYPE)


class PreProcess(Processor):
    """
    预处理协议审计的数据，查询IP的地理位置信息，判断IP是否是内网，是否是ipv6
    """

    def __init__(self, current: datetime):
        """
        :param current:
        """
        super().__init__(current)
        location, _ = Location.objects.get_or_create(id=1)
        self.default = IPRecord('', location.country, location.province,
                                location.city, location.latitude,
                                location.longitude)

    def process(self, data: Dict):
        """
        {'id': 1234, 'src_ip': '123.1.11.1', 'src_mac': '00:0C:29:45:C6:DC',
         'src_port': 58810, 'dst_ip': '192.168.111.45',
         'dst_mac': '9C:B6:D0:F0:91:9B', 'dst_port': 44818, 'l4_protocol': 1,
         'protocol': 'ENIP',
         'content': '>> Data <<:\n\nInterface Handle: 0x000cf003\nLength: 0\nStatus: No Memory Resources (0x00000002)\nCommand: Send RR Data (0x006f)\nSender Context: 0000b2001a005202\nOptions: 0x01240620\nSession Handle: 0x00020000\nTimeout: 519\nItem Count: 25632',
         'occurred_at': '2020-12-16T11:17:47+08:00'}
        :param data:
        :return:
        """
        src_ip = data['src_ip']
        src = None
        dst = None
        if src_ip:
            if ':' in src_ip:
                data['src_ipv6'] = True
                ip = IPv6Address(src_ip)
            else:
                data['src_ipv6'] = False
                ip = IPv4Address(src_ip)
            if ip.is_global:
                data['src_private'] = False
                if not data['src_ipv6']:
                    src = ip_search.search_ip_location(src_ip)
                else:
                    src = IPRecord(None)
            else:
                data['src_private'] = True
                src = self.default
        dst_ip = data['dst_ip']
        if dst_ip:
            if ':' in dst_ip:
                data['dst_ipv6'] = True
                ip = IPv6Address(dst_ip)
            else:
                data['dst_ipv6'] = False
                ip = IPv4Address(dst_ip)
            if ip.is_global:
                data['dst_private'] = False
                if not data['dst_ipv6']:
                    dst = ip_search.search_ip_location(dst_ip)
                else:
                    dst = IPRecord(None)
            else:
                data['dst_private'] = True
                dst = self.default
        data['src_record'] = src
        data['dst_record'] = dst
        super().process(data)

    def save(self):
        super().save()

    @classmethod
    def clean(cls):
        pass

    def _local_save(self, *args, **kwargs):
        pass
