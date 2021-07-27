import platform
import time
from datetime import timedelta
from typing import Dict, List

import psutil
from django.conf import settings
from django.db.models import Count, Q
from django.utils import timezone
from drf_yasg import openapi
from netifaces import ifaddresses, AF_INET
from rest_framework import serializers

from auditor.models import RiskCountry, AttackIPStatistic
from base_app.models import Device
from log.models import DeviceAllAlert, SecurityEvent, AlertDistribution, \
    IncrementDistribution
from setting.models import Setting
from statistic.helpers import IPDistributionHelper
from statistic.models import MainView, LogCenter, \
    LogStatistic, LogStatisticDay, LogDstIP, LogCategoryDistribution, \
    LogPortDistribution, SystemRunning, AlertWeekTrend
from unified_log.models import LogStatistic as LogStatic
from user.models import GROUP_AUDITOR, GROUP_ADMIN, GROUP_CONFIG_ENGINEER, \
    GROUP_SECURITY_ENGINEER, Group, UserExtension, User
from utils.helper import get_today, safe_divide, get_date
from utils.serializer import BaseSerializer


class MainViewSerializer(serializers.ModelSerializer):
    ip_count = serializers.IntegerField(label='外网IP数量')

    class Meta:
        model = MainView
        fields = ('ip_count', 'alert_count', 'un_resolved', 'log_count')


class AssetsCenterSerializer(BaseSerializer):
    """
    运营态势中心——资产中心
    """
    all = serializers.IntegerField(label='全部资产')
    security = serializers.IntegerField(label='安全资产')
    server = serializers.IntegerField(label='主机资产')
    network = serializers.IntegerField(label='网络资产')
    control = serializers.IntegerField(label='工控资产')

    def to_representation(self, instance):
        category_count = instance.values('category').annotate(
            count=Count('id')).order_by('category')
        category_dict = {i['category']: i['count'] for i in category_count}

        security = category_dict.get(Device.CATEGORY_Security, 0)
        server = category_dict.get(Device.CATEGORY_Sever, 0)
        network = category_dict.get(Device.CATEGORY_Communication, 0)
        control = category_dict.get(Device.CATEGORY_Control, 0)
        all = instance.count()
        return {'all': all, 'security': security, 'server': server,
                'network': network, 'control': control}


class MonitorCenterSerializer(BaseSerializer):
    """
    运营态势监控资产
    """
    monitor_count = serializers.IntegerField(label='监控资产数量')
    monitor_percent = serializers.IntegerField(label='性能监控比率')
    online_percent = serializers.IntegerField(label='在线比率')

    def to_representation(self, instance):
        monitor_count = instance.filter(monitor=True).count()
        all_count = instance.count()
        monitor_percent = safe_divide(monitor_count * 100, all_count)
        online_percent = safe_divide(
            instance.filter(status=Device.ONLINE).count() * 100, all_count)
        return {
            'monitor_count': monitor_count,
            'monitor_percent': monitor_percent,
            'online_percent': online_percent,
        }


class LogSerializer(serializers.SerializerMethodField):
    class Meta:
        swagger_schema_fields = openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'data': openapi.Schema(
                    '数据', type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_NUMBER)),
            }
        )


class UpdateTimeSerializer(serializers.SerializerMethodField):
    class Meta:
        swagger_schema_fields = openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema('时间', type=openapi.TYPE_STRING)
        )


class LogCenterSerializer(BaseSerializer):
    collect = LogSerializer(help_text='采集日志')
    parsed = LogSerializer(help_text='解析日志')
    update_time = UpdateTimeSerializer(help_text='统计时间')

    class Meta:
        model = LogCenter
        fields = ('collect', 'parsed', 'update_time')

    def get_collect(self, instances: List[LogCenter]) -> Dict[str, List]:
        """
        :return:
        {'data': []}
        """
        result = {'data': []}
        for instance in instances:
            result['data'].append(instance.collect)
        return result

    def get_parsed(self, instances: List[LogCenter]) -> Dict[str, List]:
        """
        :return:
        {'data': []}
        """
        result = {'data': []}
        for instance in instances:
            result['data'].append(instance.parsed)
        return result

    def get_update_time(self, instances: List[LogCenter]):
        return [timezone.localtime(r.update_time).isoformat() for r in instances]


class LogStatisticTotalSerializer(serializers.ModelSerializer):
    increase = serializers.SerializerMethodField(help_text='今日增加量')

    class Meta:
        model = LogStatistic
        fields = ('total', 'local', 'collect', 'increase')

    def get_increase(self, instance: LogStatistic):
        return instance.local_current + instance.collect_current


class LogStatisticDaySerializer(BaseSerializer):
    """
    近15天每天的本地日志量和采集日志量
    """
    update_time = UpdateTimeSerializer()
    local = LogSerializer(label='本地日志')
    collect = LogSerializer(label='采集日志')
    local_today = serializers.SerializerMethodField(label='今日本地日志')
    current_today = serializers.SerializerMethodField(label='今日采集日志')

    class Meta:
        fields = ('update_time', 'local', 'collect', 'local_today',
                  'current_today')

    def to_representation(self, instance):
        today = get_today(timezone.now())
        self.log_data = LogStatistic.objects.filter(
            update_time__gte=today).order_by('-update_time').first()

        return super().to_representation(instance)

    def get_collect(self, instances: List[LogStatisticDay]) -> Dict[str, List]:
        """
        :return:
        {'data': []}
        """
        result = {'data': []}
        for instance in instances:
            result['data'].append(instance.collect_today)
        return result

    def get_local(self, instances: List[LogStatisticDay]) -> Dict[str, List]:
        """
        :return:
        {'data': []}
        """
        result = {'data': []}
        for instance in instances:
            result['data'].append(instance.local_today)
        return result

    def get_local_today(self, instances):
        if self.log_data:
            return self.log_data.local_current
        else:
            return 0

    def get_current_today(self, instances):
        if self.log_data:
            return self.log_data.collect_current
        else:
            return 0

    def get_update_time(self, instances: List[LogStatisticDay]):
        return [timezone.localtime(r.update_time).isoformat() for r in instances]


class LogStatisticHourSerializer(BaseSerializer):
    """
    24小时内每小时的采集量
    """
    update_time = UpdateTimeSerializer()
    collect = LogSerializer(help_text='每小时的采集量')

    def get_collect(self, instances: List[LogStatistic]) -> Dict[str, List]:
        """
        :return:
        {'data': []}
        """
        result = {'data': []}
        for instance in instances:
            result['data'].append(instance.collect_hour)
        return result

    def get_update_time(self, instances: List[LogStatistic]):
        return [timezone.localtime(r.update_time).isoformat() for r in instances]


class _LogDeviceTopFiveSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', help_text='资产名称')
    percent = serializers.IntegerField(help_text='占比', default=1)

    class Meta:
        model = LogStatic
        fields = ('device_name', 'percent', 'today')


class LogDeviceTopFiveSerializer(BaseSerializer):
    data = serializers.ListField(child=_LogDeviceTopFiveSerializer())

    def to_representation(self, instances: List[LogStatic]):
        return {'data': _LogDeviceTopFiveSerializer(instances, many=True).data}


class _LogDstIPTopFiveSerializer(BaseSerializer):
    ip = serializers.CharField()
    today = serializers.IntegerField()
    percent = serializers.IntegerField()

    class Meta:
        model = LogDstIP
        fields = ('ip', 'today', 'percent')


class LogDstIPTopFiveSerializer(BaseSerializer):
    data = _LogDstIPTopFiveSerializer(many=True)

    def to_representation(self, instance):
        if not instance:
            return {'data': []}

        instances = []
        ips = instance.ip
        today = instance.today
        for i in range(len(ips)):
            try:
                percent = round(today[i] / today[0] * 100)
            except ZeroDivisionError:
                percent = 0
            instances.append(LogDstIP(ips[i], today[i], percent))
        return {'data': _LogDstIPTopFiveSerializer(instances, many=True).data}


class CategoryDistributionSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogCategoryDistribution
        fields = '__all__'


class PortDistributionSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogPortDistribution
        fields = '__all__'


class _NetworkSerializer(serializers.JSONField):
    class Meta:
        swagger_schema_fields = openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'name': openapi.Schema('网口名称', type=openapi.TYPE_STRING),
                    'speed': openapi.Schema('网速', type=openapi.TYPE_NUMBER),
                    'status': openapi.Schema('网口状态', type=openapi.TYPE_NUMBER,
                                             description='0-成功，1-失败，2-连接，3-未连接')
                }
            )
        )


class SystemRunningStatusSerializer(serializers.ModelSerializer):
    network = _NetworkSerializer()
    cpu_percent = serializers.IntegerField(label='CPU阈值')
    memory_percent = serializers.IntegerField(label='内存阈值')
    disk_percent = serializers.IntegerField(label='硬盘阈值')

    class Meta:
        model = SystemRunning
        fields = '__all__'

    def to_representation(self, instance):
        # 从setting里补上阈值信息
        setting = Setting.objects.get(pk=1)
        instance.cpu_percent = setting.cpu_alert_percent
        instance.memory_percent = setting.memory_alert_percent
        instance.disk_percent = setting.disk_alert_percent
        return super().to_representation(instance)


class SystemBasicInfoSerializer(BaseSerializer):
    run_time = serializers.ListField(child=serializers.IntegerField())
    ip = serializers.IPAddressField(label='IP地址')
    cpu_cores = serializers.IntegerField(label='CPU核心数')
    memory = serializers.IntegerField(label='内存容量')
    disk = serializers.IntegerField(label='硬盘容量')
    operation = serializers.CharField(label='操作系统')

    def to_representation(self, instance):
        return dict(
            run_time=self.get_run_time(instance),
            ip=self.get_ip(instance),
            cpu_cores=psutil.cpu_count(),
            memory=self.get_memory(instance),
            disk=self.get_disk(instance),
            operation=self.get_operation(instance),
        )

    def get_run_time(self, instance):
        boot_timestamp = psutil.boot_time()
        run_time_seconds = time.time() - boot_timestamp
        run_time_days, days_mod = divmod(run_time_seconds, 24 * 3600)
        run_time_hours, hours_mod = divmod(days_mod, 3600)
        run_time_minutes = hours_mod // 60
        run_time = [run_time_days, run_time_hours, run_time_minutes]
        return run_time

    def get_ip(self, instance):
        if settings.DEBUG:
            address = \
                ifaddresses('en0').setdefault(
                    AF_INET, [{'addr': 'No IP addr'}])[0]['addr']
        else:
            address = ifaddresses(settings.MGMT).setdefault(
                AF_INET, [{'addr': 'No IP addr'}])[0]['addr']
        return address

    def get_memory(self, instance):
        total = psutil.virtual_memory().total

        return round(total / 1024 / 1024 / 1024)

    def get_disk(self, instance):
        total = psutil.disk_usage('/').total
        return round(total / 1024 / 1024 / 1024 / 1024, 1)

    def get_operation(self, instance):
        return platform.system()


class _UserInfoSerializer(serializers.ModelSerializer):
    group = serializers.CharField(source='group.name')

    class Meta:
        model = User
        fields = ('username', 'last_login', 'group')


class UserDistributionSerializer(BaseSerializer):
    total = serializers.IntegerField(label='账户总数', default=0)
    admin = serializers.IntegerField(label='管理员数', default=0)
    config = serializers.IntegerField(label='配置工程师数', default=0)
    security = serializers.IntegerField(label='安全工程师数', default=0)
    audit = serializers.IntegerField(label='审计员数', default=0)
    un_modify_passwd = serializers.IntegerField(label='未更换密码')
    banned = serializers.IntegerField(label='被锁定用户')
    recent_thirty = serializers.IntegerField(label='30天内访问账户数')
    recent_one = _UserInfoSerializer(help_text='1天内访问账户', many=True)

    def to_representation(self, instance):
        data = dict(
            total=instance.count(),
            un_modify_passwd=self.get_un_modify_passwd(instance),
            banned=self.get_banned_user(instance),
            recent_thirty=self.get_last_login_in_30(instance),
            recent_one=self.get_last_login_one_day(instance),
        )
        data.update(self.get_groups(instance))

        return data

    def get_groups(self, instance):
        data = instance.values('group').annotate(count=Count('group')).order_by(
            'group')
        data_dict = {d['group']: d['count'] for d in data}
        result = {'admin': data_dict.get(Group.objects.get(name=GROUP_ADMIN).id, 0),
                  'config': data_dict.get(
                      Group.objects.get(name=GROUP_CONFIG_ENGINEER).id, 0),
                  'security': data_dict.get(
                      Group.objects.get(name=GROUP_SECURITY_ENGINEER).id, 0),
                  'audit': data_dict.get(Group.objects.get(name=GROUP_AUDITOR).id, 0)}

        return result

    def get_un_modify_passwd(self, instance):
        return instance.filter(un_modify_passwd=True).count()

    def get_banned_user(self, instance):
        today = get_today(timezone.now())

        return UserExtension.objects.filter(
            banned=True, last_failure__gt=today).count()

    def get_last_login_in_30(self, instance):
        last = timezone.now() - timedelta(days=30)
        return instance.filter(last_login__gt=last).count()

    def get_last_login_one_day(self, instance):
        today = get_today(timezone.now())
        return _UserInfoSerializer(instance.filter(
            last_login__gt=today).order_by('-last_login')[:8], many=True).data


class AlertProcessSerializer(serializers.ModelSerializer):
    percent = serializers.IntegerField(label='待处理安全威胁', default=100)
    high_percent = serializers.IntegerField(label='待处理高级告警', default=100)
    mid_percent = serializers.IntegerField(label='待处理中级告警', default=100)
    low_percent = serializers.IntegerField(label='待处理低级告警', default=100)

    class Meta:
        model = DeviceAllAlert
        fields = ('percent', 'high_percent', 'mid_percent', 'low_percent')

    def to_representation(self, instance: DeviceAllAlert):
        all_data = DeviceAllAlert.objects.values('level').annotate(
            count=Count('level')).order_by('level')
        security_event = SecurityEvent.objects.values('level').annotate(
            count=Count('level')).order_by('level')
        unresolved_data = DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).values(
            'level').annotate(count=Count('level')).order_by('level')
        unresolved_security_event = SecurityEvent.objects.filter(
            status_resolved=SecurityEvent.STATUS_UNRESOLVED).values(
            'level').annotate(count=Count('level')).order_by('level')

        total = 0
        unresolved = 0
        all_dict = {1: 0, 2: 0, 3: 0}
        unresolved_dict = {1: 0, 2: 0, 3: 0}
        for d in all_data:
            total += d['count']
            all_dict[d['level']] = d['count']
        for d in security_event:
            total += d['count']
            all_dict[d['level']] += d['count']
        for d in unresolved_data:
            unresolved += d['count']
            unresolved_dict[d['level']] = d['count']
        for d in unresolved_security_event:
            unresolved += d['count']
            unresolved_dict[d['level']] += d['count']

        if not total:
            return super().to_representation(instance)

        instance.percent = safe_divide(unresolved * 100, total)
        instance.high_percent = safe_divide(
            unresolved_dict.get(DeviceAllAlert.LEVEL_HIGH, 0) * 100,
            all_dict.get(DeviceAllAlert.LEVEL_HIGH, 0),
        )
        instance.mid_percent = safe_divide(
            unresolved_dict.get(DeviceAllAlert.LEVEL_MEDIUM, 0) * 100,
            all_dict.get(DeviceAllAlert.LEVEL_MEDIUM, 0),
        )
        instance.low_percent = safe_divide(
            unresolved_dict.get(DeviceAllAlert.LEVEL_LOW, 0) * 100,
            all_dict.get(DeviceAllAlert.LEVEL_LOW, 0),
        )
        return super().to_representation(instance)


class AlertThreatSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceAllAlert
        fields = ('level', 'occurred_time', 'src_ip', 'dst_ip', 'type')


class NetworkSerializer(serializers.SerializerMethodField):
    class Meta:
        swagger_schema_fields = openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'MGMT': openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'data': openapi.Schema(
                            '数据', type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_NUMBER)),
                    }
                )
            }
        )


class NetworkTrafficSerializer(BaseSerializer):
    update_time = UpdateTimeSerializer()
    network_traffic = NetworkSerializer()

    def to_representation(self, instance):
        return {
            'update_time': self.get_update_time(instance),
            'network_traffic': self.get_network_traffic(instance),
        }

    def get_update_time(self, instance):
        update_time = [i['time'] for i in instance]
        return update_time

    def get_network_traffic(self, instance):
        network_traffic = {}
        for i in instance:
            nic_infos = i['nic_infos']
            for nic in nic_infos:
                if nic['nic_name'] in network_traffic:
                    network_traffic[nic['nic_name']]['data'].append(
                        nic['traffic_rate'])
                else:
                    network_traffic[nic['nic_name']] = {
                        'data': [nic['traffic_rate']]}
        return network_traffic


class ProtocolSerializer(BaseSerializer):
    update_time = UpdateTimeSerializer()
    protocol_traffics = NetworkSerializer()

    def to_representation(self, instance):
        return {
            'update_time': self.get_update_time(instance),
            'protocol_traffics': self.get_protocol_traffics(instance),
        }

    def get_update_time(self, instance):
        update_time = [i['time'] for i in instance]
        return update_time

    def get_protocol_traffics(self, instance):
        """
        [{'proto_traffics': [{'protocol': 'CIP', 'traffic_rate': 0.0}],
             'time': '2020-12-17T13:43:27.337868+08:00'},
            {'proto_traffics': [{'protocol': 'CIP', 'traffic_rate': 0.0}],
             'time': '2020-12-17T13:43:32.337868+08:00'},]
        :param instance:
        :return:
        {
            {'CIP': {'data': []}
        }
        """
        protocol_traffic = {}
        for i in instance:
            protocol_infos = i['proto_traffics']
            for proto in protocol_infos:
                if proto['protocol'] in protocol_traffic:
                    protocol_traffic[proto['protocol']]['data'].append(
                        proto['traffic_rate'])
                else:
                    protocol_traffic[proto['protocol']] = {
                        'data': [proto['traffic_rate']]}
        return protocol_traffic


class ProtocolDistributionSerializer(BaseSerializer):
    protocols = serializers.ListField(child=serializers.CharField(),
                                      help_text='协议')
    total = serializers.ListField(child=serializers.IntegerField(),
                                  help_text='数量')

    def to_representation(self, data):
        """
        [{'protocol': 'ENIP', 'traffic': 0}, {'protocol': 'S7COMM', 'traffic': 0}, {'protocol': 'IEC61850/GOOSE', 'traffic': 0}, {'protocol': 'IEC61850/SV', 'traffic': 0}, {'protocol': 'IEC104', 'traffic': 0}, {'protocol': 'Modbus', 'traffic': 0}, {'protocol': 'DNP3', 'traffic': 0}, {'protocol': 'Fox', 'traffic': 0}, {'protocol': 'Umas', 'traffic': 0}, {'protocol': 'HTTP', 'traffic': 0}]

        :param data:
        :return:
        {
           protocols: [],
           total: [],
        }
        """
        sorted_data = sorted(data, key=lambda d: d['traffic'], reverse=True)[
                      :10]
        protocols = []
        total = []
        other = 0
        for i in sorted_data:
            protocols.append(i['protocol'])
            total.append(i['traffic'])
            other += i['traffic']
        count = 0
        for i in data:
            count += i['traffic']
        other = count - other
        protocols.append('其他')
        total.append(other)
        return {'protocols': protocols, 'total': total}


class DeviceTrafficSerializer(BaseSerializer):
    update_time = UpdateTimeSerializer()
    device_traffic = NetworkSerializer()

    def to_representation(self, instance):
        return {
            'update_time': self.get_update_time(instance),
            'device_traffic': self.get_device_traffic(instance),
        }

    def get_update_time(self, instance):
        update_time = [i['time'] for i in instance]
        return update_time

    def get_device_traffic(self, instance):
        """
        [{'dev_traffics': [
    {'dev_id': '30', 'dev_ip': '192.12.15.1', 'dev_name': '测试1215301',
     'traffic_rate': 0.0}], 'time': '2020-12-17T15:28:52.394790+08:00'}, {
    'dev_traffics': [
        {'dev_id': '30', 'dev_ip': '192.12.15.1',
         'dev_name': '测试1215301', 'traffic_rate': 0.0}],
    'time': '2020-12-17T15:28:57.394790+08:00'}, {
    'dev_traffics': [
        {'dev_id': '30', 'dev_ip': '192.12.15.1',
         'dev_name': '测试1215301', 'traffic_rate': 0.0}],
    'time': '2020-12-17T15:29:02.394790+08:00'}]
        :param instance:
        :return:
        """
        device_traffic = {}
        for i in instance:
            device_infos = i['dev_traffics']
            for device in device_infos:
                if device['dev_ip'] in device_traffic:
                    device_traffic[device['dev_ip']]['data'].append(
                        device['traffic_rate'])
                else:
                    device_traffic[device['dev_ip']] = {
                        'data': [device['traffic_rate']]}
        return device_traffic


class UnResolvedAlertSerializer(BaseSerializer):
    data = serializers.IntegerField(label='未处理告警')


class _DeviceSerializer(BaseSerializer):
    add = serializers.IntegerField(label='新增资产数量')
    risk = serializers.IntegerField(label='存在安全告警和安全威胁的资产数量')
    total = serializers.IntegerField(label='所有资产')
    log = serializers.IntegerField(label='开启了日志监控资产')
    log_percent = serializers.IntegerField(label='开启了日志监控资产的比例')
    performance = serializers.IntegerField(label='开启了性能监控资产')
    performance_percent = serializers.IntegerField(label='开启了性能监控资产的比例')
    online = serializers.IntegerField(label='在线资产的数量')
    online_percent = serializers.IntegerField(label='在线资产的比例')
    responsible_user = serializers.ListField(child=serializers.CharField(),
                                             label='负责人')

    def to_representation(self, instance):
        return super().to_representation(instance)


class DeviceDistributionSerializer(BaseSerializer):
    security = _DeviceSerializer(help_text='安全资产')
    network = _DeviceSerializer(help_text='网络资产')
    server = _DeviceSerializer(help_text='主机资产')
    control = _DeviceSerializer(help_text='工控资产')

    class _Device:
        """
        序列化内部类，只用于_DeviceSerializer
        """

        def __init__(self, add=0, risk=0, total=0, log=0, performance=0,
                     online=0, responsible_user=None):
            self.add = add
            self.risk = risk
            self.total = total
            self.log = log
            self.performance = performance
            self.online = online
            self.responsible_user = responsible_user or []
            self.log_percent = safe_divide(self.log * 100, self.total)
            self.performance_percent = safe_divide(self.performance * 100,
                                                   self.total)
            self.online_percent = safe_divide(self.online * 100, self.total)

    class Meta:
        queryset = Device.objects.all()

    def get_queryset(self):
        return self.Meta.queryset

    def to_representation(self, instance):
        data = {
            Device.CATEGORY_Security: {},
            Device.CATEGORY_Communication: {},
            Device.CATEGORY_Sever: {},
            Device.CATEGORY_Control: {},
        }

        total = self.get_count()
        risk = self.get_risk()
        add = self.get_add()
        log = self.get_log()
        performance = self.get_performance()
        online = self.get_online()
        responsible_user = self.get_responsible_user()
        for key in data.keys():
            data[key]['total'] = total.get(key, 0)
            data[key]['risk'] = risk[key]
            data[key]['add'] = add.get(key, 0)
            data[key]['log'] = log.get(key, 0)
            data[key]['performance'] = performance.get(key, 0)
            data[key]['online'] = online.get(key, 0)
            data[key]['responsible_user'] = responsible_user[key]

        security = self._Device(**data[Device.CATEGORY_Security])
        network = self._Device(**data[Device.CATEGORY_Communication])
        server = self._Device(**data[Device.CATEGORY_Sever])
        control = self._Device(**data[Device.CATEGORY_Control])

        return {
            'security': _DeviceSerializer(security).data,
            'network': _DeviceSerializer(network).data,
            'server': _DeviceSerializer(server).data,
            'control': _DeviceSerializer(control).data,
        }

    def get_count(self) -> Dict[int, int]:
        result = self.get_queryset().values(
            'category').annotate(count=Count('id')).order_by('category')
        # <QuerySet [{'category': 1, 'count': 24}, {'category': 2, 'count': 4},
        # {'category': 3, 'count': 7}, {'category': None, 'count': 1}]>
        data = {i['category']: i['count'] for i in result}
        return data

    def get_risk(self) -> Dict[int, int]:
        """
        统计各个类别下含有未处理的安全威胁+安全事件的资产总数
        :return:
        """
        data = {
            Device.CATEGORY_Security: 0,
            Device.CATEGORY_Communication: 0,
            Device.CATEGORY_Sever: 0,
            Device.CATEGORY_Control: 0,
        }
        for category in data.keys():
            security_event = SecurityEvent.objects.filter(
                status_resolved=SecurityEvent.STATUS_UNRESOLVED,
                device__category=category
            ).values_list('device__id').distinct('device__id').order_by(
                'device__id')
            security = set(security_event)
            device_alert = DeviceAllAlert.objects.filter(
                status_resolved=SecurityEvent.STATUS_UNRESOLVED,
                device__category=category
            ).values_list('device__id').distinct('device__id').order_by(
                'device__id')
            alert = set(device_alert)
            data[category] = len(security | alert)
        return data

    def get_add(self) -> Dict[int, int]:
        result = self.get_queryset().filter(created_at__gte=get_today()).values(
            'category').annotate(count=Count('id')).order_by('category')
        # <QuerySet [{'category': 1, 'count': 24}, {'category': 2, 'count': 4},
        # {'category': 3, 'count': 7}, {'category': None, 'count': 1}]>
        data = {i['category']: i['count'] for i in result}
        return data

    def get_log(self) -> Dict[int, int]:
        result = self.get_queryset().filter(log_status=True).values(
            'category').annotate(count=Count('id')).order_by('category')
        # <QuerySet [{'category': 1, 'count': 24}, {'category': 2, 'count': 4},
        # {'category': 3, 'count': 7}, {'category': None, 'count': 1}]>
        data = {i['category']: i['count'] for i in result}
        return data

    def get_performance(self) -> Dict[int, int]:
        result = self.get_queryset().filter(monitor=True).values(
            'category').annotate(count=Count('id')).order_by('category')
        # <QuerySet [{'category': 1, 'count': 24}, {'category': 2, 'count': 4},
        # {'category': 3, 'count': 7}, {'category': None, 'count': 1}]>
        data = {i['category']: i['count'] for i in result}
        return data

    def get_online(self) -> Dict[int, int]:
        result = self.get_queryset().filter(status=Device.ONLINE).values(
            'category').annotate(count=Count('id')).order_by('category')
        # <QuerySet [{'category': 1, 'count': 24}, {'category': 2, 'count': 4},
        # {'category': 3, 'count': 7}, {'category': None, 'count': 1}]>
        data = {i['category']: i['count'] for i in result}
        return data

    def get_responsible_user(self) -> Dict[int, List[str]]:
        # <QuerySet [{'category': 1, 'responsible_user': 'Nishino', 'count': 23},
        # {'category': 1, 'responsible_user': '', 'count': 1},
        # {'category': 2, 'responsible_user': 'Nishino', 'count': 3},
        result = self.get_queryset().values(
            'category', 'responsible_user').annotate(
            count=Count('id')).order_by(
            'category', '-count')
        data = {
            Device.CATEGORY_Security: [],
            Device.CATEGORY_Communication: [],
            Device.CATEGORY_Sever: [],
            Device.CATEGORY_Control: [],
        }

        for res in result:
            if not res['category'] or not res['responsible_user']:
                continue
            if len(data[res['category']]) >= 3:
                continue
            else:
                data[res['category']].append(res['responsible_user'])
        return data


class DeviceCountSerializer(BaseSerializer):
    count = serializers.IntegerField(label='资产总数')

    def to_representation(self, instance):
        return {'count': instance.count()}


class _RiskDeviceSerializer(BaseSerializer):
    ip = serializers.CharField(label='IP地址')
    count = serializers.IntegerField(label='安全告警数')
    percent = serializers.IntegerField(label='安全告警数占最多的百分比')


class RiskDeviceTopFiveSerializer(BaseSerializer):
    data = _RiskDeviceSerializer(many=True)

    class _Device:
        def __init__(self, ip, count, max_count):
            self.ip = ip
            self.count = count
            self.percent = safe_divide(self.count * 100, max_count)

    def to_representation(self, instance):
        """
        统计今日资产安全事件+安全威胁排名
        :param instance:
        :return:
        """
        today = get_today(timezone.now())
        data = {}
        event_rank = SecurityEvent.objects.filter(
            occurred_time__gte=today).values(
            'device__ip').annotate(
            count=Count('id')).order_by('device__ip', '-count')
        alert_rank = DeviceAllAlert.objects.filter(
            occurred_time__gte=today).values(
            'device__ip').annotate(
            count=Count('id')).order_by('device__ip', '-count')
        for i in event_rank:
            data[i['device__ip']] = i['count']
        for i in alert_rank:
            if i['device__ip'] in data:
                data[i['device__ip']] += i['count']
            else:
                data[i['device__ip']] = i['count']
        if None in data:
            data.pop(None)
        max_count = max(data.values() or [0])
        data_list = [self._Device(ip=ip, count=count, max_count=max_count)
                     for ip, count in data.items() if ip]

        data_list = sorted(data_list, key=lambda x: x.count, reverse=True)[:5]

        return {'data': _RiskDeviceSerializer(data_list, many=True).data}


class _IPSerializer(BaseSerializer):
    gateway = serializers.CharField(label='网段')
    ip_count = serializers.IntegerField(label='当前网段使用IP')
    update_count = serializers.IntegerField(label='最近修改IP数量')
    used = serializers.ListField(child=serializers.CharField(),
                                 help_text='已用IP')
    updated = serializers.ListField(child=serializers.CharField(),
                                    help_text='修改IP')


class IPSerializer(BaseSerializer):
    ip = _IPSerializer()


class IPDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('ip', 'name', 'location', 'responsible_user')


class AssetsIPSerializer(BaseSerializer):
    segments = serializers.IntegerField(label='网段数')
    ip_count = serializers.IntegerField(label='已用IP')
    ip_distribution = IPSerializer()
    devices = serializers.ListField(child=IPDeviceSerializer(),
                                    help_text='资产信息')

    def to_representation(self, instance):
        distribution = IPDistributionHelper()
        distribution.analyze_distribution()

        devices = IPDeviceSerializer(Device.objects.all(), many=True).data
        devices = {d['ip']: d for d in devices}

        return {
            'segments': distribution.segments,
            'ip_count': distribution.count,
            'ip_distribution': distribution.distribution,
            'devices': devices,
        }


class _ExternlaIPSerializer(BaseSerializer):
    ip = serializers.CharField(label='IP地址')
    count = serializers.IntegerField(label='通讯次数')
    percent = serializers.IntegerField(label='占最多的百分比')


class ExternalIPTopSerializer(BaseSerializer):
    data = serializers.ListField(child=_ExternlaIPSerializer())

    def to_representation(self, instance):
        if not instance:
            return {'data': instance}
        top = instance[0]['count']
        for i in instance:
            i['percent'] = safe_divide(i['count'] * 100, top)
        return {'data': instance}


class _PortSerializer(BaseSerializer):
    port = serializers.CharField(label='端口')
    count = serializers.CharField(label='数量')


class PortRankSerializer(BaseSerializer):
    src_port = _PortSerializer(many=True)
    dst_port = _PortSerializer(many=True)

    def to_representation(self, instance):
        return instance


class IPRankSerializer(BaseSerializer):
    src_ip = _ExternlaIPSerializer(many=True)
    dst_ip = _ExternlaIPSerializer(many=True)

    def to_representation(self, instance):
        return instance


class _IPMapSerializer(BaseSerializer):
    src_c = serializers.CharField(label='源IP国家')
    src_p = serializers.CharField(label='源IP省份')
    src_city = serializers.CharField(label='源IP城市')
    src_lat = serializers.FloatField(label='源IP纬度')
    src_long = serializers.FloatField(label='源IP经度')
    dst_c = serializers.CharField(label='目的IP国家')
    dst_p = serializers.CharField(label='目的IP省份')
    dst_city = serializers.CharField(label='目的IP城市')
    dst_lat = serializers.FloatField(label='目的IP纬度')
    dst_long = serializers.FloatField(label='目的IP经度')
    count = serializers.IntegerField(label='通信次数')


class IPMapSerializer(BaseSerializer):
    map = serializers.ListField(child=_IPMapSerializer())

    def to_representation(self, instance):
        return {'map': _IPMapSerializer(instance, many=True).data}


class _RiskSrcCountrySerializer(serializers.ModelSerializer):
    """
    威胁源地图TOP5
    """

    class Meta:
        model = RiskCountry
        fields = ('country', 'count')


class RiskSrcCountrySerializer(BaseSerializer):
    data = serializers.ListField(child=_RiskSrcCountrySerializer())

    def to_representation(self, instance):
        return {'data': _RiskSrcCountrySerializer(instance, many=True).data}


class _AttackSerializer(serializers.ModelSerializer):
    alert = serializers.IntegerField(label='安全威胁')
    high_alert = serializers.IntegerField(label='高级安全威胁')
    mid_alert = serializers.IntegerField(label='中级安全威胁')
    low_alert = serializers.IntegerField(label='低级安全威胁')

    class Meta:
        model = AttackIPStatistic
        fields = ('count', 'src_ip', 'foreign', 'alert', 'high_alert',
                  'mid_alert', 'low_alert')


class AttackStatisticSerializer(BaseSerializer):
    realtime = _AttackSerializer()
    total = _AttackSerializer()

    def to_representation(self, instance):
        # 积累值的攻击源IP和境外访问IP去重规则和今日不一样
        history_src_ip = instance.pop('history_src_ip')
        history_foreign = instance.pop('history_foreign')
        today = get_today(timezone.now())
        today_attack = AttackIPStatistic(**instance)
        today_alert = DeviceAllAlert.objects.filter(
            occurred_time__gte=today).values('level').annotate(
            count=Count('level')).order_by('level')
        today_alert_dict = {i['level']: i['count'] for i in today_alert}
        today_attack.high_alert = today_alert_dict.get(
            DeviceAllAlert.LEVEL_HIGH, 0)
        today_attack.mid_alert = today_alert_dict.get(
            DeviceAllAlert.LEVEL_MEDIUM, 0)
        today_attack.low_alert = today_alert_dict.get(DeviceAllAlert.LEVEL_LOW,
                                                      0)
        today_attack.alert = sum(today_alert_dict.values())

        total_attack, _ = AttackIPStatistic.objects.get_or_create(id=1)
        total_attack.count += today_attack.count
        total_attack.src_ip += history_src_ip
        total_attack.foreign += history_foreign
        total_alert = DeviceAllAlert.objects.values('level').annotate(
            count=Count('level')).order_by('level')
        total_alert_dict = {i['level']: i['count'] for i in total_alert}
        total_attack.high_alert = total_alert_dict.get(
            DeviceAllAlert.LEVEL_HIGH, 0)
        total_attack.mid_alert = total_alert_dict.get(
            DeviceAllAlert.LEVEL_MEDIUM, 0)
        total_attack.low_alert = total_alert_dict.get(DeviceAllAlert.LEVEL_LOW,
                                                      0)
        total_attack.alert = sum(total_alert_dict.values())

        return {'realtime': _AttackSerializer(today_attack).data,
                'total': _AttackSerializer(total_attack).data}


class DeviceAlertDistributionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertDistribution
        fields = ('scan', 'flaw', 'penetration', 'apt', 'other')


class DeviceAlertSerializer(serializers.ModelSerializer):
    country = serializers.CharField(source='src_country', allow_null=True)
    province = serializers.CharField(source='src_province', allow_null=True)
    city = serializers.CharField(source='src_city', allow_null=True)

    class Meta:
        model = DeviceAllAlert
        fields = (
            'src_ip', 'category', 'occurred_time', 'country', 'province',
            'city')


class DeviceAlertDateSerializer(BaseSerializer):
    date = serializers.DateField()
    count = serializers.IntegerField()
    list = serializers.ListField(child=DeviceAlertSerializer())

    def to_representation(self, instance):
        return {'date': instance['date'], 'count': instance['count'],
                'list': DeviceAlertSerializer(instance['list'], many=True).data}


class DeviceAlertRealtimeSerializer(BaseSerializer):
    realtime_info = serializers.ListField(child=DeviceAlertDateSerializer())

    def to_representation(self, instance):
        data: List[DeviceAllAlert] = instance[:10]

        result_dict = {}
        for d in data:
            date_ = get_date(d.occurred_time)
            if date_ in result_dict:
                result_dict[date_]['list'].append(d)
            else:
                result_dict[date_] = {
                    'count': DeviceAllAlert.objects.filter(
                        occurred_time__date=date_).count(),
                    'date': date_,
                    'list': [d]
                }
        result = list(result_dict.values())
        return {
            'realtime_info': DeviceAlertDateSerializer(result, many=True).data}


class ListItemSerializer(BaseSerializer):
    class Meta:
        swagger_schema_fields = openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'data': openapi.Schema(
                    '数据', type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_NUMBER)),
            }
        )


class AlertIncrementSerializer(BaseSerializer):
    scan = ListItemSerializer()
    flaw = ListItemSerializer()
    penetration = ListItemSerializer()
    apt = ListItemSerializer()
    other = ListItemSerializer()


class IncrementTrendSerializer(BaseSerializer):
    update_time = UpdateTimeSerializer()
    trend = AlertIncrementSerializer()

    def to_representation(self, instance: List[IncrementDistribution]):
        data = {
            'update_time': [],
            'scan': {'data': []},
            'flaw': {'data': []},
            'penetration': {'data': []},
            'apt': {'data': []},
            'other': {'data': []},
        }
        if not instance:
            return data
        instance = instance[::-1]
        data['update_time'] = self.get_update_time(instance)
        for i in instance:
            data['scan']['data'].append(i.scan)
            data['flaw']['data'].append(i.flaw)
            data['penetration']['data'].append(i.penetration)
            data['apt']['data'].append(i.apt)
            data['other']['data'].append(i.other)
        return data

    def get_update_time(self, instances: List[IncrementDistribution]):
        return [timezone.localtime(r.update_time).isoformat() for r in instances]


class TypeTrendSerializer(BaseSerializer):
    type = serializers.IntegerField(label='安全威胁类型')
    trend = serializers.ListField(child=serializers.IntegerField(label='每日数量'))
    total = serializers.IntegerField(label='7日总数')


class CategoryTrendSerializer(BaseSerializer):
    category = serializers.IntegerField(label='安全威胁类别')
    type_info = TypeTrendSerializer()


class AlertWeekTrendSerializer(BaseSerializer):
    update_time = UpdateTimeSerializer()
    category_info = serializers.ListField(child=CategoryTrendSerializer())

    def to_representation(self, instance: List[AlertWeekTrend]):
        instance = instance[::-1]

        data = [
            {'category': 1,
             'type_info': self.get_trend_data([i.scan for i in instance])},
            {'category': 2,
             'type_info': self.get_trend_data([i.flaw for i in instance])},
            {'category': 3, 'type_info': self.get_trend_data(
                [i.penetration for i in instance])},
            {'category': 4,
             'type_info': self.get_trend_data([i.apt for i in instance])},
            {'category': 5,
             'type_info': self.get_trend_data([i.other for i in instance])},
        ]

        return {'category_info': data,
                'update_time': self.get_update_time(instance)}

    def get_trend_data(self, data: List[Dict]):
        """
        获取安全威胁下的各个类型的7日数据
        :param category: 1, 2, 3, 4, 5
        :param data: [{type1: xx, type2:xx}, {type1: xx, type2:xx}]
        :return:
        """
        type_dict = {}  # 1: {'trend': [1, 2,3], 'total': 12}
        for d in data:
            for t, count in d.items():
                if t in type_dict:
                    type_dict[t]['trend'].append(count)
                    type_dict[t]['total'] += count
                else:
                    type_dict[t] = {'trend': [count], 'total': count,
                                    'type': int(t)}
        result = list(type_dict.values())
        return result

    def get_update_time(self, instance):
        return [timezone.localtime(i.update_time).isoformat() for i in instance]


class LockedUsernameSerializer(serializers.ModelSerializer):
    mark = serializers.CharField()

    class Meta:
        model = UserExtension
        fields = ('name', 'last_failure', 'mark')

    def to_representation(self, instance: UserExtension):
        self.setting, _ = Setting.objects.get_or_create(id=1)
        instance.mark = self.get_mark(instance)

        return super().to_representation(instance)

    def get_mark(self, instance: UserExtension):
        try:
            User.objects.get(username=instance.name)
            duration = (timezone.now() - instance.last_failure).total_seconds()
            left = self.setting.lockout_duration * 60 - duration
            if left < 0:
                mark = '剩余时间0分钟，重新登录即可解锁'
            else:
                mark = '剩余时间{}分钟'.format(round(left / 60))
        except User.DoesNotExist:
            mark = '非系统用户'
        return mark


class AbnormalLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserExtension
        fields = ('name', 'ip', 'last_login')


class AbnormalIPSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    country = serializers.CharField(allow_null=True)
    province = serializers.CharField(allow_null=True)
    city = serializers.CharField(allow_null=True)
    update_time = serializers.DateTimeField()

    def to_internal_value(self, data):
        return super().to_internal_value(data)


class AbnormalBehaviorSerializer(BaseSerializer):
    locked_user = serializers.ListField(
        child=LockedUsernameSerializer(label='锁定账户'))
    abnormal_login = serializers.ListField(
        child=AbnormalLoginSerializer(label='异常登录'))
    external_ip = serializers.ListField(
        child=AbnormalIPSerializer(label='外网访问IP'))
    foreign_ip = serializers.ListField(
        child=AbnormalIPSerializer(label='境外访问IP'))

    def to_representation(self, instance):
        ip_queue = instance['ip_queue']
        instance = instance['instance']
        external_ip = AbnormalIPSerializer(data=ip_queue.get_external_ip(),
                                           many=True)
        external_ip.is_valid(raise_exception=True)
        foreign_ip = AbnormalIPSerializer(data=ip_queue.get_foreign_ip(),
                                          many=True)
        foreign_ip.is_valid(raise_exception=True)

        return {
            'locked_user': LockedUsernameSerializer(
                instance.filter(banned=True).order_by(
                    '-last_failure')[:5], many=True).data,
            'abnormal_login': AbnormalLoginSerializer(
                instance.filter(
                    Q(last_login__hour__gte=0, last_login__hour__lte=6) |
                    Q(last_login__hour__gte=22,
                      last_login__hour__lte=23)).order_by('-last_login')[:5],
                many=True
            ).data,
            'external_ip': external_ip.data,
            'foreign_ip': foreign_ip.data
        }


class _AlertRealtimeSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceAllAlert
        fields = ('occurred_time', 'category', 'type', 'src_ip', 'src_country',
                  'src_province', 'src_city', 'dst_ip', 'dst_country',
                  'dst_province', 'dst_city', 'src_port', 'dst_port')


class AlertRealtimeSerializer(BaseSerializer):
    count = serializers.IntegerField(label='今日安全威胁')
    results = _AlertRealtimeSerializer(many=True)

    def to_representation(self, instance):
        return {
            'count': instance.count(),
            'results': _AlertRealtimeSerializer(instance[:20], many=True).data,
        }


class AttackLocationSerializer(BaseSerializer):
    location = serializers.CharField(label='资产位置')
    count = serializers.IntegerField(label='告警数量')


class IPAlertSerializer(serializers.ModelSerializer):
    count = serializers.IntegerField(label='今日IP下威胁数量')

    class Meta:
        model = DeviceAllAlert
        fields = ('src_ip', 'src_country', 'src_province', 'src_city', 'count',
                  'occurred_time')

    def to_representation(self, instance: DeviceAllAlert):
        today = get_today(timezone.now())
        instance.count = DeviceAllAlert.objects.filter(
            occurred_time__gte=today, src_ip=instance.src_ip).count()
        return super().to_representation(instance)


class AlertIPRankSerializer(BaseSerializer):
    external = IPAlertSerializer(many=True)
    private = IPAlertSerializer(many=True)

    def to_representation(self, instance):
        return {
            'external': IPAlertSerializer(
                instance.filter(src_private=False)[:10], many=True).data,
            'private': IPAlertSerializer(instance.filter(src_private=True)[:10],
                                         many=True).data,
        }
