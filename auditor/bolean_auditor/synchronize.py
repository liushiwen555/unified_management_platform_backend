import logging
import traceback
from abc import abstractmethod, ABC
from collections import OrderedDict
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Dict, Optional, List

import requests
from django.conf import settings
from django.db.models import F, Count
from django.utils import timezone

from auditor.bolean_auditor.faker_auditor import faker_auditor
from auditor.bolean_auditor.process_protocol import Processor
from auditor.models import Device, AuditorBlackList
from auditor.serializers import AuditSysAlertUploadSerializer
from log.models import DeviceAllAlert
from log.serializers import AuditSecAlertToDeviceAllAlertSerializer
from setting.models import Location
from statistic.serializers import DeviceAlertRealtimeSerializer, \
    AlertRealtimeSerializer, \
    AttackLocationSerializer, AlertIPRankSerializer, AlertProcessSerializer, \
    AlertThreatSerializer
from utils.helper import get_today
from utils.helper import send_websocket_message
from utils.ip_search import ip_search
from utils.unified_redis import rs

logger = logging.getLogger()
WEBSOCKET_TYPE = 'unified_push'


class DeviceCache(object):
    key_pattern = 'audit-device-cache'
    expire = 5

    def __init__(self, capacity: int = 200):
        self._cache = OrderedDict()
        self.cap = capacity
        self.count = 0

    def key(self, ip: str):
        return self.key_pattern + '-' + ip

    def get(self, ip: Optional[str]) -> Optional[int]:
        if not ip or self.is_banned_ip(ip):
            # 有些ip不在综管的资产列表，就不要频繁去查了，放入banned ip里
            return None
        device_id = self._cache.get(ip, None)
        if device_id:
            self._cache.move_to_end(ip)
        else:
            device_id = self._set(ip)
        return device_id

    def _set(self, ip: str) -> Optional[Device]:
        try:
            device = Device.objects.get(ip=ip)
        except Device.DoesNotExist:
            self.set_banned_ip(ip)  # 不在综管的资产中的进入ban池
            return None
        if self.count >= self.cap:
            self._cache.popitem(last=False)
        else:
            self.count += 1
        self._cache[ip] = device.id
        return device.id

    def is_banned_ip(self, ip: str):
        return rs.exists(self.key(ip))

    def set_banned_ip(self, ip: str):
        rs.set(name=self.key(ip), value=1, ex=self.expire)


class Synchronize(ABC):
    uri = None
    scheme = settings.AUDIT_SCHEME
    port = settings.AUDIT_PORT

    def __init__(self, device: Device):
        self.device = device

    def synchronize(self):
        try:
            response = self.request_for_data()
            self.save(response)
        except Exception as e:
            logging.error('审计同步失败')
            logging.error(e)

    @abstractmethod
    def request_for_data(self, *args, **kwargs) -> Dict:
        pass

    @abstractmethod
    def save(self, data: Dict):
        pass

    def do_request(self, payload=None):
        if settings.TEST:
            return self.do_faker_request(payload)
        headers = {'secret': self.device.secret}
        response = requests.get('{}://{}:{}/{}'.format(
            self.scheme, self.device.ip, self.port, self.uri
        ), params=payload, headers=headers, verify=False)
        response.raise_for_status()
        response = response.json()
        return response

    def do_faker_request(self, payload):
        return faker_auditor.get(self.uri, payload)


class AuditorSynchronize(Synchronize):
    uri = 'v2/unified-management/sec-alert/'
    audit_event_blacklist = 1

    def __init__(self, device: Device, current: datetime):
        super().__init__(device)
        self.current = current
        self._cache = DeviceCache()
        self.location, _ = Location.objects.get_or_create(id=1)

    def request_for_data(self) -> Dict:
        payload = {'start_id': self.device.audit_sec_alert_max_id,
                   'category': self.audit_event_blacklist}
        response = self.do_request(payload)
        return response

    def save(self, response: Dict):
        """

        :param response:
        {
            'max_id': XXX,
            'log_list': XXX,
        }
        :return:
        """
        log_list = response['log_list']
        transfer_list = []
        for log in log_list:
            transfer_log = {}
            for k, v in log.items():
                if k not in ['is_test', 'pkt']:
                    transfer_log[k] = v
            transfer_log['device'] = self._cache.get(log.get('dst_ip'))
            transfer_log['occurred_time'] = log.get('last_at')
            self.update_black_list_info(log['other_info'].get('sid'),
                                        transfer_log)
            self.update_location(transfer_log)
            transfer_list.append(transfer_log)
        serializer = AuditSecAlertToDeviceAllAlertSerializer(
            data=transfer_list, many=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        self.device.audit_sec_alert_max_id = response['max_id']
        self.device.save(update_fields=['audit_sec_alert_max_id'])
        self.process(transfer_list)
        self.websocket_send()

    def blacklist_sec_desc(self, log: Dict, black: AuditorBlackList):
        content = f'流量 {log["src_ip"]}:{log["src_port"]} -> ' \
                  f'{log["dst_ip"]}:{log["dst_port"]} ' \
                  f'符合已有威胁特征【{black.name}】'
        return content

    def update_black_list_info(self, sid: int, transfer_log: Dict):
        """
        根据审计同步过来的黑名单告警里的sid，查询对应的安全威胁类别和类型,处理建议
        并更新在transfer_log里
        :param sid: 黑名单的唯一表示，可以使用AuditorBlackList查询到黑名单
        :param transfer_log: 综管存储需要的内容
        :return:
        """
        try:
            black = AuditorBlackList.objects.get(sid=sid)
            transfer_log['category'] = black.alert_category
            transfer_log['type'] = black.alert_type
            transfer_log['suggest_desc'] = black.suggest
            transfer_log['sec_desc'] = self.blacklist_sec_desc(
                transfer_log, black)
        except AuditorBlackList.DoesNotExist:
            transfer_log['category'] = 1
            transfer_log['type'] = 1

    def process(self, data: List):
        try:
            processor = Processor.process_alert_list(self.current)
            for d in data:
                processor.process(d)
            processor.save()
        except Exception as e:
            logger.error('同步事件审计，统计威胁分布出错, {}'.format(e))
            traceback.print_exc()

    def update_location(self, data):
        src_ip = data.get('src_ip')
        if src_ip:
            if ':' in src_ip:
                ip = IPv6Address(src_ip)
                data['src_private'] = ip.is_private
            else:
                ip = IPv4Address(src_ip)
                if ip.is_global:
                    location = ip_search.search_ip_location(src_ip)
                    data['src_country'] = location.country
                    data['src_province'] = location.province
                    data['src_city'] = location.city
                    data['src_private'] = False
                else:
                    data['src_country'] = self.location.country
                    data['src_province'] = self.location.province
                    data['src_city'] = self.location.city
                    data['src_private'] = True
        dst_ip = data.get('dst_ip')
        if dst_ip:
            if ':' in dst_ip:
                ip = IPv6Address(dst_ip)
                data['dst_private'] = ip.is_private
            else:
                ip = IPv4Address(dst_ip)
                if ip.is_global:
                    location = ip_search.search_ip_location(dst_ip)
                    data['dst_country'] = location.country
                    data['dst_province'] = location.province
                    data['dst_city'] = location.city
                    data['dst_private'] = False
                else:
                    data['dst_country'] = self.location.country
                    data['dst_province'] = self.location.province
                    data['dst_city'] = self.location.city
                    data['dst_private'] = True

    def websocket_send(self):
        """
        安全威胁同步结束后推送最新的告警数据
        """
        self.security_websocket_send()
        self.attack_websocket_send()
        self.main_websocket_send()

    def security_websocket_send(self):
        """
        推送安全态势中心——威胁时序图
        """
        serializer = DeviceAlertRealtimeSerializer(
            DeviceAllAlert.objects.order_by('-occurred_time'))
        message = {
            'message': 'security',
            'data': {
                'device_alert_realtime': serializer.data,
            }
        }
        send_websocket_message('security', message, WEBSOCKET_TYPE)

    def attack_websocket_send(self):
        """
        推送安全态势中心——攻击画像的内容
        """
        alert_ip = AlertIPRankSerializer(DeviceAllAlert.objects.filter(
            occurred_time__gte=get_today(self.current)
        ).order_by('-occurred_time')).data

        locations = DeviceAllAlert.objects.filter(
            occurred_time__gte=get_today(self.current)).values(
            'device__location').annotate(count=Count('id')).annotate(
            location=F('device__location')).order_by('-count')
        locations = [i for i in locations if i['location']]
        serializer = AttackLocationSerializer(data=locations[:5], many=True)
        serializer.is_valid(raise_exception=True)
        attack_location = serializer.data

        alert_realtime = AlertRealtimeSerializer(DeviceAllAlert.objects.filter(
            occurred_time__gte=get_today(self.current)).order_by(
            '-occurred_time')).data
        message = {
            'message': 'attack',
            'data': {
                'alert_ip_rank': alert_ip,
                'attack_location': attack_location,
                'alert_realtime': alert_realtime,
            }
        }

        send_websocket_message('attack', message, WEBSOCKET_TYPE)

    def main_websocket_send(self):
        """
        推送运营态势中心——告警处理的最新数据
        """
        alert_process = AlertProcessSerializer(DeviceAllAlert.objects.all())
        alert_threat = AlertThreatSerializer(
            DeviceAllAlert.objects.filter().order_by('-occurred_time')[:7],
            many=True)
        message = {
            'message': 'main',
            'data': {
                'alert_process': alert_process.data,
                'alert_threat': alert_threat.data,
            }
        }
        send_websocket_message('main', message, WEBSOCKET_TYPE)


class AuditorNetwork(Synchronize):
    uri = 'v2/unified-management/nic-traffic-line-chart/'

    def request_for_data(self) -> Dict:
        payload = {'interval': 5, 'span': 5}
        response = self.do_request(payload)
        return response

    def save(self, data: Dict):
        pass


class AuditorSynchronizeLog(Synchronize):
    uri = 'v2/unified-management/sys-alert/'

    def request_for_data(self) -> Dict:
        payload = {'start_id': self.device.audit_sys_alert_max_id}
        response = self.do_request(payload)
        return response

    def save(self, data: Dict):
        log_list = data['log_list']
        transfer_list = []
        for log in log_list:
            transfer_log = {}
            for k, v in log.items():
                if k not in ['is_test', 'pkt']:
                    transfer_log[k] = v
            transfer_log['device'] = self.device.id
            transfer_log['occurred_time'] = log.get('occurred_at')
            transfer_list.append(transfer_log)
        serializer = AuditSysAlertUploadSerializer(data=transfer_list,
                                                   many=True)
        serializer.is_valid(raise_exception=True)
        serializer.save(device=self.device)
        self.device.audit_sys_alert_max_id = data['max_id']
        self.device.save(update_fields=['audit_sys_alert_max_id'])


class AuditorProtocolTraffics(AuditorNetwork):
    uri = 'v2/unified-management/proto-traffic-stat/'


class AuditorProtocolDistribution(AuditorNetwork):
    uri = 'v2/unified-management/proto-pie-chart/'


class AuditorDeviceTraffics(AuditorNetwork):
    uri = 'v2/unified-management/dev-traffic-stat/'


class AuditorProtocol(Synchronize):
    """
    同步协议审计数据，做IP地理信息解析，IP端口排名
    """
    uri = 'v2/unified-management/packets-upload/'
    synchronize_time_key = 'auditor_protocol_synchronize_time'

    def __init__(self, device, current: datetime, interval=5000):
        """
        :param device: 审计资产
        :param current: 当前时间
        :param interval: 请求的数据量
        """
        super().__init__(device)
        self.current = current.replace(minute=0, second=0, microsecond=0)
        self.interval = interval

    def request_for_data(self):
        """
        请求当前时间之前interval期间内的协议数据
        :return:
        """
        headers = {'secret': self.device.secret}
        result = []

        start_id = self.device.audit_protocol_max_id
        while True:
            end_id = start_id + self.interval
            payload = dict(start_id=start_id, end_id=end_id)
            response = self.request(payload)
            result.extend(response['log_list'])
            max_id = response['max_id']
            if max_id < end_id - 1:
                break
            else:
                start_id = response['max_id']

        return result, max_id

    def request(self, payload):
        try:
            response = self.do_request(payload)
        except ConnectionError:
            # 协议审计获取失败时，当前最大id就是请求的开始id
            response = {'max_id': payload['start_id'], 'log_list': []}
        return response

    def save(self, data):
        processor = Processor.process_list(self.current)
        for d in data:
            processor.process(d)
        processor.save()

    def synchronize(self):
        proto_data, max_id = self.request_for_data()
        self.save(proto_data[::-1])
        self.device.audit_protocol_max_id = max_id
        self.device.save(update_fields=['audit_protocol_max_id'])


class AuditorProtocolInterface(Synchronize):
    uri = 'v2/unified-management/packets/'

    def request_for_data(self, *args, **kwargs) -> Dict:
        payload = kwargs
        response = self.do_request(payload)
        return response

    def save(self, data: Dict):
        pass


if __name__ == '__main__':
    auditor = Device.objects.get(id=5)
    # sync = AuditorProtocolTraffics(auditor)
    # sync = AuditorProtocolDistribution(auditor)
    # sync = AuditorDeviceTraffics(auditor)
    sync = AuditorProtocol(auditor, timezone.now())
    data = sync.request_for_data()
    print(data)
