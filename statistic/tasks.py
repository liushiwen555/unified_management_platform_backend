import subprocess
import time
from datetime import datetime, timedelta
from typing import Dict, List

import psutil
from django.conf import settings
from django.contrib.postgres.fields.jsonb import KeyTransform
from django.db.models import Count
from elasticsearch_dsl import A

from auditor.bolean_auditor import AuditorProtocol
from auditor.bolean_auditor.process_protocol import \
    AttackIPRank as AttackIPRankProcess
from auditor.bolean_auditor.process_protocol import ProtocolIPRank as IPRank
from auditor.bolean_auditor.process_protocol import TodayExternalIP, PortRank, \
    IPSource
from auditor.models import AuditSysAlert, AuditSecAlert, AttackIPStatistic
from base_app.models import Device
from firewall.models import FirewallSysEvent, FirewallSecEvent
from log.models import DeviceAllAlert, UnifiedForumLog, SecurityEvent
from log.security_event import NetworkEvent, LogAbnormalEvent, SecurityEventLog, \
    AlertEvent, HighAlertEvent
from statistic.models import MainView, AssetsCenter, MonitorCenter, LogCenter, \
    LogStatistic, LogStatisticDay, LogDstIPTopFive, LogCategoryDistribution, \
    LogPortDistribution, SystemRunning, IPDistribution, ExternalIPTopFive, \
    ProtocolPortRank, ProtocolIPRank, AlertWeekTrend, AttackIPRank
from statistic.serializers import MainViewSerializer, LogCenterSerializer, \
    SystemRunningStatusSerializer, AlertWeekTrendSerializer, \
    LogStatisticTotalSerializer, LogStatisticDaySerializer, \
    LogStatisticHourSerializer, \
    LogDeviceTopFiveSerializer, LogDstIPTopFiveSerializer, \
    CategoryDistributionSerializer, PortDistributionSerializer
from unified_log.elastic.elastic_client import client
from unified_log.elastic.elastic_model import BaseDocument
from unified_log.models import LogStatistic as DeviceLog
from utils.constants import CATEGORY_DICT
from utils.constants import NETWORK_STATUS
from utils.helper import get_today, get_last_day, safe_divide
from utils.runnable import TaskRun, TaskRunWebsocket


class MainViewTask(TaskRunWebsocket):
    """
    获取运营态势主视图的内容  60分钟周期
    左上：【全部告警】累计的安全事件与安全威胁总量。
    左下：【待处理告警】未处理的安全事件与安全威胁总量。
    右上：【全部日志】累计获取的日志总量（含本地日志和采集日志）。
    右下：【外网IP】环境中当天（0点时起）出现的非管理资产的IP个数（去重）。
    """
    room_group_name = 'main'

    @classmethod
    def alert_count(cls) -> int:
        return DeviceAllAlert.objects.count() + SecurityEvent.objects.count()

    @classmethod
    def un_resolved(cls) -> int:
        """
        安全事件+安全威胁
        需要判断安全事件和安全威胁数是否需要产生安全事件
        :return:
        """
        # 未解决安全事件数
        security_count = SecurityEvent.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()
        # 未解决安全威胁数
        alert_count = DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()
        # 未解决高级安全威胁数
        high_alert_count = DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED,
            level=DeviceAllAlert.LEVEL_HIGH
        ).count()
        security_event = SecurityEventLog(security_count)
        security_event.generate()
        alert_event = AlertEvent(alert_count)
        alert_event.generate()
        high_alert_event = HighAlertEvent(high_alert_count)
        high_alert_event.generate()

        return security_count + alert_count

    @classmethod
    def log_count(cls):
        """
        Elasticsearch采集日志+本机日志+防火墙日志+审计日志
        """
        search = BaseDocument.search()
        es_count = search.count()
        unified_count = 0
        for model in [UnifiedForumLog, FirewallSecEvent, FirewallSysEvent,
                      AuditSysAlert, AuditSecAlert]:
            unified_count += model.objects.count()
        return es_count + unified_count

    @classmethod
    def run(cls, current: datetime):
        data = dict(
            alert_count=cls.alert_count(),
            un_resolved=cls.un_resolved(),
            log_count=cls.log_count(),
            update_time=current,
        )
        main_view = MainView.objects.create(**data)
        cls.send(current, main_view)
        return main_view

    @classmethod
    def send(cls, current: datetime, main: MainView):
        ip_source = IPSource(current)
        attack_data = ip_source.get_attack_data()
        attack_ip = AttackIPStatistic.objects.first()
        if attack_ip:
            main.ip_count = attack_ip.external_ip + attack_data[
                'external_ip']
        else:
            main.ip_count = attack_data['external_ip']
        serializer = MainViewSerializer(main)
        message = {
            'message': cls.room_group_name,
            'data': {
                'main': serializer.data
            }
        }
        cls.websocket_send(message)


class AssetsCenterTask(TaskRun):
    """
    模块：运营态势中心
    更新周期：60分钟
    描述：记录资产的监控比例和在线比例
    备注：页面数据改为实时获取了，这里的定时任务可以删除
    """

    @classmethod
    def run(cls, current: datetime):
        assets_center = cls.get_assets(current)
        assets_center.save()
        return assets_center

    @classmethod
    def get_assets(cls, current: datetime) -> AssetsCenter:
        category_count = Device.objects.values('category').annotate(
            count=Count('id')).order_by('category')
        category_dict = {i['category']: i['count'] for i in category_count}

        security = category_dict.get(Device.CATEGORY_Security, 0)
        server = category_dict.get(Device.CATEGORY_Sever, 0)
        network = category_dict.get(Device.CATEGORY_Communication, 0)
        control = category_dict.get(Device.CATEGORY_Control, 0)

        assets_center = AssetsCenter(
            all=(security + server + network + control),
            security=security, server=server, network=network, control=control,
            update_time=current)
        return assets_center


class MonitorCenterTask(TaskRun):
    """
    模块：运营态势中心
    更新周期：60分钟
    描述：记录资产的监控比例和在线比例
    备注：页面数据改为实时获取了，这里的定时任务可以删除
    """

    @classmethod
    def run(cls, current: datetime):
        monitor_count = Device.objects.filter(monitor=True).count()
        all_count = Device.objects.all().count()
        monitor_percent = safe_divide(monitor_count * 100, all_count)
        online_percent = safe_divide(
            Device.objects.filter(status=Device.ONLINE).count() * 100,
            all_count)
        return MonitorCenter.objects.create(
            monitor_count=monitor_count, monitor_percent=monitor_percent,
            online_percent=online_percent, update_time=current
        )


class LogCenterTask(TaskRunWebsocket):
    """
    模块：运营态势中心
    更新周期：10分钟
    描述：统计每十分钟的采集日志数量
    """
    room_group_name = 'main'

    @classmethod
    def run(cls, current: datetime):
        last = current - timedelta(minutes=10)
        search = BaseDocument.search()
        search = search.filter('range', timestamp={'gte': last, 'lte': current})
        collect = search.count()
        parsed = search.filter('term', status=True).count()

        log_center = LogCenter.objects.create(collect=collect, parsed=parsed,
                                              update_time=current)
        serializer = LogCenterSerializer(
            LogCenter.objects.order_by('-update_time')[:10][::-1])
        message = {
            'message': cls.room_group_name,
            'data': {
                'log_center': serializer.data,
            }
        }
        cls.websocket_send(message)
        return log_center


class LogStatisticTask(TaskRunWebsocket):
    """
    模块：日志中心
    更新周期：1小时
    描述：统计累计的、当天的日志采集量
    """
    room_group_name = 'log'

    @classmethod
    def run(cls, current: datetime):
        today = get_today(current)
        last_hour = current - timedelta(hours=1)
        last = LogStatistic.objects.first()

        data = dict(
            local=cls.get_local(current, last),
            collect=cls.get_collect(current, last),
            local_current=cls.get_local_current(today, current),
            collect_current=cls.get_collect_current(today, current),
            local_hour=cls.get_local_hour(last_hour, current),
            collect_hour=cls.get_collect_hour(last_hour, current),
            update_time=current,
        )
        data['total'] = data['local'] + data['collect']
        cls.check_abnormal(data['total'], today)
        log_statistic = LogStatistic.objects.create(**data)
        cls.websocket_send(log_statistic)
        return log_statistic

    @classmethod
    def websocket_send(cls, log_statistic: LogStatistic):
        message = {
            'message': cls.room_group_name,
            'data': {
                'total': LogStatisticTotalSerializer(log_statistic).data,
                'hour_trend': LogStatisticHourSerializer(
                    LogStatistic.objects.all().order_by('-update_time')[:24][
                    ::-1]).data
            }
        }
        super().websocket_send(message)

    @classmethod
    def get_local(cls, current: datetime, last: LogStatistic):
        """
        本机系统日志，如果有以前的记录，就通过以前的记录累加
        """
        unified_count = 0
        for model in [UnifiedForumLog, FirewallSecEvent, FirewallSysEvent,
                      AuditSysAlert]:
            if last:
                unified_count += model.objects.filter(
                    occurred_time__lt=current, occurred_time__gte=last.update_time).count()
            else:
                unified_count += model.objects.filter(occurred_time__lt=current).count()
        if last:
            unified_count += last.local
        return unified_count

    @classmethod
    def get_collect(cls, current: datetime, last: LogStatistic):
        search = BaseDocument.search()
        if last:
            es_count = search.filter(
                'range', timestamp={'gte': last.update_time, 'lt': current}).count()
            es_count += last.collect
        else:
            es_count = search.count()
        return es_count

    @classmethod
    def get_local_current(cls, today: datetime, current: datetime):
        """
        本机系统日志, 当日
        """
        unified_count = 0
        for model in [UnifiedForumLog, FirewallSecEvent, FirewallSysEvent,
                      AuditSysAlert]:
            unified_count += model.objects.filter(
                occurred_time__gte=today, occurred_time__lt=current).count()
        return unified_count

    @classmethod
    def get_collect_current(cls, today: datetime, current: datetime):
        """
        采集系统日志, 当日
        """
        search = BaseDocument.search()
        search = search.filter('range', timestamp={'gte': today, 'lt': current})
        collect = search.count()
        return collect

    @classmethod
    def get_local_hour(cls, last_hour: datetime, current: datetime):
        """
        本机系统日志, 上个小时
        """
        unified_count = 0
        for model in [UnifiedForumLog, FirewallSecEvent, FirewallSysEvent,
                      AuditSysAlert]:
            unified_count += model.objects.filter(
                occurred_time__gte=last_hour, occurred_time__lt=current).count()
        return unified_count

    @classmethod
    def get_collect_hour(cls, last_hour: datetime, current: datetime):
        search = BaseDocument.search()
        search = search.filter('range',
                               timestamp={'gte': last_hour, 'lt': current})
        collect = search.count()
        return collect

    @classmethod
    def check_abnormal(cls, count: int, last: datetime):
        event = LogAbnormalEvent(count, last)
        event.generate()


class LogStatisticDayTask(TaskRunWebsocket):
    room_group_name = 'log'

    @classmethod
    def run(cls, current: datetime):
        last = get_last_day(current)
        today = get_today(current)
        data = dict(
            local_today=cls.get_local_today(last, today),
            collect_today=cls.get_collect_today(last, today),
            update_time=last,
        )
        log_statistic_day = LogStatisticDay.objects.create(**data)
        message = {
            'message': cls.room_group_name,
            'data': {
                'day_trend': LogStatisticDaySerializer(
                    LogStatisticDay.objects.order_by('-update_time')[:15][
                    ::-1]).data
            }
        }
        cls.websocket_send(message)
        return log_statistic_day

    @classmethod
    def get_local_today(cls, last: datetime, today: datetime):
        unified_count = 0
        for model in [UnifiedForumLog, FirewallSecEvent, FirewallSysEvent,
                      AuditSysAlert, AuditSecAlert]:
            unified_count += model.objects.filter(
                occurred_time__gte=last, occurred_time__lte=today).count()
        return unified_count

    @classmethod
    def get_collect_today(cls, last: datetime, today: datetime):
        search = BaseDocument.search()
        search = search.filter('range', timestamp={'gte': last, 'lte': today})
        collect = search.count()
        return collect


class LogDstIPTopFiveTask(TaskRunWebsocket):
    """
    模块：日志中心——今日目的IP TOP5
    更新周期： 60分钟
    描述：当天日志的目的IP TOP5
    """
    room_group_name = 'log'

    @classmethod
    def run(cls, current: datetime):
        search = BaseDocument.search()
        today = get_today(current)
        port = A('terms', field='dst_ip')
        search = search.filter('range',
                               timestamp={'gte': today, 'lte': current})
        search.aggs.bucket('ip-terms', port)
        body = {'size': 0}
        body.update(search.to_dict())
        result = client.search(BaseDocument.index_pattern(), body)
        if 'aggregations' not in result:
            return LogDstIPTopFive.objects.create(ip=[], today=[],
                                                  update_time=current)
        buckets = result['aggregations']['ip-terms']['buckets']
        buckets = sorted(buckets, key=lambda x: x['doc_count'], reverse=True)

        ip = []
        total = []
        for b in buckets[:5]:
            ip.append(b['key'])
            total.append(b['doc_count'])
        data = dict(
            ip=ip, today=total, update_time=current
        )
        log = LogDstIPTopFive.objects.create(**data)
        message = {
            'message': cls.room_group_name,
            'data': {
                'dst_ip_top_five': LogDstIPTopFiveSerializer(log).data,
            }
        }
        cls.websocket_send(message)
        return log


class LogCategoryDistributionTask(TaskRunWebsocket):
    """
    模块：日志中心——今日日志分布
    更新周期： 60分钟
    描述：今日安全资产、主机资产、网络资产、工控资产的日志数量
    """
    room_group_name = 'log'

    @classmethod
    def run(cls, current: datetime):
        search = BaseDocument.search()
        last = get_today(current)
        category = A('terms', field='dev_category')
        search = search.filter('range', timestamp={'gte': last, 'lte': current})
        search.aggs.bucket('category-terms', category)
        body = {'size': 0}
        body.update(search.to_dict())
        result = client.search(BaseDocument.index_pattern(), body)

        if 'aggregations' in result:
            # [{'key': '安全资产', 'doc_count': 1120}, {'key': '网络资产', 'doc_count': 3}]
            buckets = result['aggregations']['category-terms']['buckets']
        else:
            buckets = []

        data = {'update_time': current}
        for bucket in buckets:
            data[CATEGORY_DICT[bucket['key']]] = bucket['doc_count']
        log = LogCategoryDistribution.objects.create(**data)
        message = {
            'message': cls.room_group_name,
            'data': {
                'category_distribution': CategoryDistributionSerializer(
                    log).data
            }
        }
        cls.websocket_send(message)
        return log


class LogPortDistributionTask(TaskRunWebsocket):
    """
    模块：日志中心——今日端口分布
    更新周期： 60分钟
    描述：当天日志的端口分布，只统计数量排名前10的端口，剩余的数量放到其他里面
    """
    room_group_name = 'log'

    @classmethod
    def run(cls, current: datetime):
        search = BaseDocument.search()
        last = get_today(current)
        port = A('terms', field='dst_port')
        search = search.filter('range', timestamp={'gte': last, 'lte': current})
        search.aggs.bucket('port-terms', port)
        body = {'size': 0}
        body.update(search.to_dict())
        result = client.search(BaseDocument.index_pattern(), body)
        if 'aggregations' in result:
            buckets = result['aggregations']['port-terms']['buckets']
            # 统计排名前10的端口
            sorted_buckets = sorted(buckets, key=lambda x: x['doc_count'],
                                    reverse=True)
            other = result['aggregations']['port-terms']['sum_other_doc_count']
        else:
            sorted_buckets = []
            other = 0
        ports = []
        total = []
        for b in sorted_buckets[:10]:
            ports.append(b['key'])
            total.append(b['doc_count'])
        ports.append('其他')
        total.append(other)

        data = dict(
            ports=ports, total=total, update_time=current
        )
        log = LogPortDistribution.objects.create(**data)
        message = {
            'message': cls.room_group_name,
            'data': {
                'port_distribution': PortDistributionSerializer(log).data
            }
        }
        cls.websocket_send(message)
        return log


class DeviceLogCountTask(TaskRunWebsocket):
    """
    模块：日志中心——今日资产日志TOP5
    更新周期： 60分钟
    描述：每隔1小时，定时统计所有资产的日志量
    """
    room_group_name = 'log'

    @classmethod
    def run(cls, current: datetime):
        devices = Device.objects.filter(log_status=True)
        for device in devices:
            device_log, _ = DeviceLog.objects.get_or_create(device=device)
            device_log.today = cls.get_today(device.id, current)
            device_log.total = cls.get_total(device.id)
            device_log.update_time = cls.get_update_time(device.id)
            device_log.save()

    @classmethod
    def get_total(cls, dev_id):
        search = BaseDocument.search()
        search = search.filter('term', dev_id=dev_id)
        return search.count()

    @classmethod
    def get_today(cls, dev_id, current: datetime):
        today = get_today(current)
        search = BaseDocument.search()
        search = search.filter('term', dev_id=dev_id).filter(
            'range', timestamp={'gte': today})
        return search.count()

    @classmethod
    def get_update_time(cls, dev_id):
        search = BaseDocument.search()
        search = search.filter('term', dev_id=dev_id).sort('-timestamp')
        data = search[:1].execute()
        if not data:
            return None
        else:
            return data.hits[0]['timestamp']

    @classmethod
    def device_top_five(cls):
        instances = DeviceLog.objects.all().order_by('-today')[:5]
        for instance in instances:
            if instances[0].today != 0:
                instance.percent = round(
                    instance.today / instances[0].today * 100)
            else:
                instance.percent = 0
        serializer = LogDeviceTopFiveSerializer(instances)
        message = {
            'message': cls.room_group_name,
            'data': {
                'collect_top_five': serializer.data
            }
        }
        cls.websocket_send(message)


class SystemRunningTask(TaskRunWebsocket):
    mgmt = settings.MGMT
    interfaces = [mgmt] + settings.INTERFACES
    key = 'LAN'
    room_group_name = 'running'

    @classmethod
    def run(cls, current: datetime):
        data = dict(
            cpu=round(psutil.cpu_percent()),
            memory=round(psutil.virtual_memory().percent),
            disk=round(psutil.disk_usage('/').percent),
            network=cls.get_network_traffic(current),
        )
        running = SystemRunning.objects.create(**data)
        cls.websocket_send({'message': cls.room_group_name,
                            'data': {
                                'system_status': SystemRunningStatusSerializer(
                                    running).data}})
        return running

    @classmethod
    def get_network_traffic(cls, current) -> List[Dict[str, str]]:
        result = {'MGMT': {'speed': 0, 'status': NETWORK_STATUS['unplugged']}}
        last = psutil.net_io_counters(pernic=True)
        time.sleep(1)
        now = psutil.net_io_counters(pernic=True)
        status = cls.get_network_status()

        for i, name in enumerate(cls.interfaces):
            speed = round((now[name].bytes_recv - last[name].bytes_recv) / 1024,
                          2)
            s = status[name]
            if cls.mgmt == name:
                nic_name = 'MGMT'
            else:
                nic_name = cls.key + str(i)
            result[nic_name] = {'speed': speed, 'status': s}

            if s == NETWORK_STATUS['link beat detected'] and \
                    not cls.check_interface_normal(i, current):
                event = NetworkEvent(name=nic_name)
                event.generate()

        result_list = [{'name': key, 'speed': val['speed'],
                        'status': val['status']} for key, val in result.items()]
        return result_list

    @classmethod
    def get_network_status(cls) -> Dict[str, int]:
        status = {i: NETWORK_STATUS['link beat detected'] for i in
                  cls.interfaces}

        try:
            process = subprocess.run(['ifplugstatus'], stdout=subprocess.PIPE)
            result = process.stdout.decode('utf-8').split('\n')
            for res in result:
                if not res:
                    continue
                name, status_ = res.split(': ')
                status[name] = NETWORK_STATUS[status_]
        except FileNotFoundError:
            pass

        return status

    @classmethod
    def check_interface_normal(cls, pos: int, current: datetime):
        """
        判断网口是否连接正常，判断依据是5分钟内网速是不是都大于0
        :param pos: 网口的位置
        :param current: 当前时间
        :return:
        """
        speed = SystemRunning.objects.filter(
            update_time__gt=current - timedelta(minutes=5)).annotate(
            val=KeyTransform(str(pos), 'network')).annotate(
            speed=KeyTransform('speed', 'val'))
        total = 0
        for s in speed:
            total += s.speed or 0
        if total < 0.1:
            return False
        return True


class AssetsIPDistributionTask(TaskRun):
    """
    每天凌晨统计一次，记录昨天的资产IP使用情况
    用于和今日资产IP使用情况比较
    """

    @classmethod
    def run(cls, current: datetime) -> IPDistribution:
        ips = Device.objects.values_list('ip', flat=True)
        distribution = cls.analyze_ip_distribution(ips)
        ip_dis, _ = IPDistribution.objects.get_or_create(id=1)
        ip_dis.ips = distribution
        ip_dis.update_time = current
        ip_dis.save()
        return ip_dis

    @classmethod
    def analyze_ip_distribution(cls, ips: List[str]) -> Dict[str, List[str]]:
        """
        分析IP所属的网段和网段下的IP
        :param ips:
        :return:
        """
        distribution = {}
        for ip in ips:
            gateway = '.'.join(ip.split('.')[:3] + ['1/24'])
            if gateway in distribution:
                distribution[gateway].append(ip)
            else:
                distribution[gateway] = [ip]
        return distribution


class ExternalIPTopTask(TaskRun):
    """
    模块：资产中心——外联资产TOP5
    更新周期：1天
    描述：每天凌晨统计一次，保存昨天的外联资产Top5，保存后删除redis的记录
    """

    @classmethod
    def run(cls, current: datetime):
        last = get_last_day(current)
        external = TodayExternalIP(last)
        data = external.get_top_n()

        ips = []
        count = []
        for d in data:
            ips.append(d['ip'])
            count.append(d['count'])
        ExternalIPTopFive.objects.create(ips=ips, count=count,
                                         update_time=current)
        external.clean()


class ProtocolPortRankTask(TaskRun):
    """
    模块：流量中心——今日端口统计
    更新周期：1天
    描述：每天凌晨统计一次，保存昨天的端口排名统计，保存后删除redis数据
    """

    @classmethod
    def run(cls, current: datetime):
        last = get_last_day(current)
        port = PortRank(last)
        data = port.get_top_n()

        data['update_time'] = current
        ProtocolPortRank.objects.create(**data)
        port.clean()


class ProtocolIPRankTask(TaskRun):
    """
    模块：流量中心——今日IP统计
    更新周期：1天
    描述：每天凌晨统计一次，保存昨天的IP排名统计，保存后删除redis数据
    """

    @classmethod
    def run(cls, current: datetime):
        last = get_last_day(current)
        ip_rank = IPRank(last)
        data = ip_rank.get_top_n()

        data['update_time'] = current
        ProtocolIPRank.objects.create(**data)
        ip_rank.clean()


class AttackIPRankTask(TaskRun):
    """
    模块：流量中心——今日IP统计
    更新周期：1天
    描述：每天凌晨统计一次，保存昨天的IP排名统计，保存后删除redis数据
    """

    @classmethod
    def run(cls, current: datetime):
        last = get_last_day(current)
        ip_rank = AttackIPRankProcess(last)
        data = ip_rank.get_top_n()

        data['update_time'] = current
        AttackIPRank.objects.create(**data)
        ip_rank.clean()


class AuditorProtocolSynchronizeTask(TaskRun):
    """
    模块：协议审计
    更新周期：1小时
    描述：每小时查询一次协议审计上一个小时的数据并更新
    """

    @classmethod
    def run(cls, current: datetime):
        auditor = Device.objects.filter(type=Device.AUDITOR,
                                        register_status=Device.REGISTERED)
        if not auditor.exists():
            return None
        auditor = auditor[0]
        sync = AuditorProtocol(auditor, current)
        sync.synchronize()


class AttackIPStatisticTask(TaskRun):
    """
    模块：安全态势中心
    更新周期：1天
    描述：将昨天统计的攻击次数，攻击源IP个数存储下来
    """

    @classmethod
    def run(cls, current: datetime) -> AttackIPStatistic:
        last = get_last_day(current)
        statistic, _ = AttackIPStatistic.objects.get_or_create(id=1)
        attack = IPSource(last)
        attack_data = attack.get_attack_data()
        statistic.count += int(attack_data['count'])
        statistic.src_ip += int(attack_data['history_src_ip'])
        statistic.foreign += int(attack_data['history_foreign'])
        statistic.external_ip += int(attack_data['external_ip'])
        statistic.save()

        attack.clean()
        return statistic


class AlertWeekTrendTask(TaskRunWebsocket):
    """
    模块：安全态势——异常行为——安全威胁本周趋势
    更新周期：1天
    描述：统计昨天的新增的安全威胁，分类记录下来
    """
    room_group_name = 'abnormal'

    @classmethod
    def run(cls, current: datetime):
        last = get_last_day(current)
        result = DeviceAllAlert.objects.filter(occurred_time__gte=last).values(
            'category', 'type').annotate(count=Count('id')).order_by(
            'category', 'type')
        trend = [
            {r: 0 for r in DeviceAllAlert.SCAN_TYPE},
            {r: 0 for r in DeviceAllAlert.FLAW_TYPE},
            {r: 0 for r in DeviceAllAlert.PENETRATION_TYPE},
            {r: 0 for r in DeviceAllAlert.APT_TYPE},
            {r: 0 for r in DeviceAllAlert.OTHER_TYPE},
        ]
        for r in result:
            category = r['category'] - 1
            type_ = r['type']
            if type_ in trend[category]:
                trend[category][type_] = r['count']
        scan = trend[0]
        flaw = trend[1]
        penetration = trend[2]
        apt = trend[3]
        other = trend[4]

        cls.websocket_send({
            'message': cls.room_group_name,
            'data': {
                'alert_week': AlertWeekTrendSerializer(
                    AlertWeekTrend.objects.order_by('-update_time')[:7]).data
            }
        })
        return AlertWeekTrend.objects.create(
            scan=scan, flaw=flaw, penetration=penetration, apt=apt, other=other,
            update_time=last
        )
