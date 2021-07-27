import json

from asgiref.sync import async_to_sync
from channels.generic.websocket import WebsocketConsumer
from channels.layers import get_channel_layer
from django.db.models import F, Count
from django.utils import timezone

from auditor.bolean_auditor.process_protocol import TodayExternalIP, PortRank, \
    ProtocolIPRank, IPSource, AttackIPRank, IPQueueProcess
from auditor.models import RiskCountry, AttackIPStatistic
from base_app.models import Device
from log.models import DeviceAllAlert, AlertDistribution, IncrementDistribution
from statistic.models import MainView, LogCenter, \
    LogStatistic, LogStatisticDay, LogDstIPTopFive, \
    LogCategoryDistribution, LogPortDistribution, SystemRunning, AlertWeekTrend
from statistic.serializers import MainViewSerializer, AssetsCenterSerializer, \
    MonitorCenterSerializer, LogCenterSerializer, LogStatisticTotalSerializer, \
    LogStatisticDaySerializer, LogStatisticHourSerializer, \
    LogDeviceTopFiveSerializer, LogDstIPTopFiveSerializer, \
    CategoryDistributionSerializer, PortDistributionSerializer, \
    SystemRunningStatusSerializer, AlertProcessSerializer, \
    AlertThreatSerializer, \
    DeviceDistributionSerializer, DeviceCountSerializer, \
    RiskDeviceTopFiveSerializer, AssetsIPSerializer, ExternalIPTopSerializer, \
    PortRankSerializer, IPRankSerializer, \
    IPMapSerializer, RiskSrcCountrySerializer, AttackStatisticSerializer, \
    DeviceAlertDistributionSerializer, DeviceAlertRealtimeSerializer, \
    IncrementTrendSerializer, AlertWeekTrendSerializer, \
    AbnormalBehaviorSerializer, AlertRealtimeSerializer, \
    AttackLocationSerializer, AlertIPRankSerializer
from unified_log.models import LogStatistic as LogStatic
from user.models import UserExtension
from utils.helper import get_today


class StatisticNotification(WebsocketConsumer):
    """
    安全中心统计数据websocket推送
    """
    room_name = None
    room_group_name = None
    type_ = 'unified_push'

    def initial_group(self):
        self.room_name = self.channel_name

    def connect(self):
        self.accept()
        self.initial_group()

        async_to_sync(self.channel_layer.group_add)(
            self.room_group_name, self.room_name, )

    def disconnect(self, code):
        async_to_sync(self.channel_layer.group_discard)(
            self.room_group_name, self.channel_name)

    def receive(self, text_data=None, bytes_data=None):
        self.manual_send({'data': 'ack'})

    def unified_push(self, event):
        message = event['message']
        data = event.get('data')

        self.send(text_data=json.dumps({'message': message, 'data': data}))

    @classmethod
    def manual_send(cls, message):
        assert cls.room_group_name is not None
        layer = get_channel_layer()
        message['message'] = cls.room_group_name
        message['type'] = cls.type_
        async_to_sync(layer.group_send)(cls.room_group_name, message)


class SecurityConsumer(StatisticNotification):
    """
    安全态势中心主屏
    """
    room_group_name = 'security'
    current = None

    def initial_group(self):
        self.room_name = self.channel_name
        self.current = timezone.now()

    def connect(self):
        super().connect()
        message = {
            'data': {
                'risk_country_top': self.risk_country_top(),
                'attack_statistic': self.attack_statistic(),
                'device_alert_distribution': self.device_alert_distribution(),
                'device_alert_realtime': self.device_alert_realtime(),
                'alert_trend': self.alert_trend(),
            }}
        self.manual_send(message)

    def risk_country_top(self):
        serializer = RiskSrcCountrySerializer(
            RiskCountry.objects.order_by('-count')[:5])
        return serializer.data

    def attack_statistic(self):
        serializer = AttackStatisticSerializer(
            IPSource(self.current).get_attack_data())
        return serializer.data

    def device_alert_distribution(self):
        serializer = DeviceAlertDistributionSerializer(
            AlertDistribution.objects.first())
        return serializer.data

    def device_alert_realtime(self):
        serializer = DeviceAlertRealtimeSerializer(
            DeviceAllAlert.objects.order_by('-occurred_time'))
        return serializer.data

    def alert_trend(self):
        serializer = IncrementTrendSerializer(
            IncrementDistribution.objects.order_by('-update_time')[:48])
        return serializer.data


class IPMAPConsumer(StatisticNotification):
    """
    安全态势主屏——IP地图
    """
    room_group_name = 'ip_map'
    current = None

    def initial_group(self):
        self.current = timezone.now()
        super().initial_group()

    def connect(self):
        super().connect()
        message = {
            'message': self.room_group_name,
            'data': {
                'ip_map': self.ip_map(),
            }
        }
        self.manual_send(message)

    def ip_map(self):
        ip_source = IPSource(self.current)
        serializer = IPMapSerializer(ip_source.get_city_data())
        return serializer.data


class SystemRunningConsumer(StatisticNotification):
    room_group_name = 'running'

    def connect(self):
        super().connect()
        message = {
            'data': {
                'system_status': SystemRunningStatusSerializer(
                    SystemRunning.objects.first()).data
            }
        }

        self.manual_send(message)


class AttackConsumer(StatisticNotification):
    room_group_name = 'attack'
    current = None

    def initial_group(self):
        self.current = timezone.now()
        super().initial_group()

    def connect(self):
        super().connect()
        message = {
            'data': {
                'attack_ip_rank': self.attack_ip_rank(),
                'alert_ip_rank': self.alert_ip_rank(),
                'attack_location': self.attack_location(),
                'alert_realtime': self.alert_realtime(),
            }
        }
        self.manual_send(message)

    def attack_ip_rank(self):
        attack = AttackIPRank(self.current).get_top_n()
        return attack

    def alert_ip_rank(self):
        data = DeviceAllAlert.objects.filter(
            occurred_time__gte=get_today(self.current)
        ).order_by('-occurred_time')
        serializer = AlertIPRankSerializer(data)
        return serializer.data

    def attack_location(self):
        data = DeviceAllAlert.objects.filter(
            occurred_time__gte=get_today(self.current)).values(
            'device__location').annotate(count=Count('id')).annotate(
            location=F('device__location')).order_by('-count')
        data = [i for i in data if i['location']]
        serializer = AttackLocationSerializer(data=data[:5], many=True)
        serializer.is_valid(raise_exception=True)
        return serializer.data

    def alert_realtime(self):
        data = DeviceAllAlert.objects.filter(
            occurred_time__gte=get_today(self.current)).order_by(
            '-occurred_time')
        serializer = AlertRealtimeSerializer(data)
        return serializer.data


class AbnormalConsumer(StatisticNotification):
    room_group_name = 'abnormal'
    current = None

    def initial_group(self):
        self.current = timezone.now()
        super().initial_group()

    def connect(self):
        super().connect()
        """
        {
            locked_user: [],
            abnormal_login: [],
            external_ip: [],
            foreign_ip: [],
            alert_week: {}
        }
        """
        data = AbnormalBehaviorSerializer(
            {'instance': UserExtension.objects.all(),
             'ip_queue': IPQueueProcess(self.current)}).data
        data['alert_week'] = self.alert_week()
        message = {
            'message': self.room_group_name,
            'data': data,
        }

        self.manual_send(message)

    def alert_week(self):
        serializer = AlertWeekTrendSerializer(
            AlertWeekTrend.objects.order_by('-update_time')[:7])
        return serializer.data


class MainConsumer(StatisticNotification):
    """
    运营态势中心Websocket推送
    """
    room_group_name = 'main'
    current = None

    def initial_group(self):
        self.current = timezone.now()
        super().initial_group()

    def connect(self):
        super().connect()
        message = {
            'message': self.room_group_name,
            'data': {
                'main': self.main_view(),
                'assets_center': self.assets_center(),
                'monitor_center': self.monitor_center(),
                'log_center': self.log_center(),
                'alert_process': self.alert_process(),
                'alert_threat': self.alert_threat(),
            }
        }
        self.manual_send(message)

    def main_view(self):
        ip_source = IPSource(self.current)
        main = MainView.objects.first()
        attack_data = ip_source.get_attack_data()
        attack_ip = AttackIPStatistic.objects.first()
        if attack_ip:
            main.ip_count = attack_ip.external_ip + attack_data[
                'external_ip']
        serializer = MainViewSerializer(main)
        return serializer.data

    def assets_center(self):
        serializer = AssetsCenterSerializer(Device.objects.all())

        return serializer.data

    def monitor_center(self):
        serializer = MonitorCenterSerializer(Device.objects.all())
        return serializer.data

    def log_center(self):
        """
        运营态势——日志中心
        """
        serializer = LogCenterSerializer(
            LogCenter.objects.order_by('-update_time')[:10][::-1])

        return serializer.data

    def alert_process(self):
        """
        运营态势——告警处理百分比
        """
        serializer = AlertProcessSerializer(DeviceAllAlert.objects.all())

        return serializer.data

    def alert_threat(self):
        """
        运营态势——实时威胁监控
        """
        serializer = AlertThreatSerializer(
            DeviceAllAlert.objects.filter().order_by('-occurred_time')[:7],
            many=True)
        return serializer.data


class AssetsCenterConsumer(StatisticNotification):
    """
    资产中心推送
    """
    room_group_name = 'assets'
    current = None

    def initial_group(self):
        self.current = timezone.now()
        super().initial_group()

    def connect(self):
        super().connect()
        message = {
            'message': self.room_group_name,
            'data': {
                'category_distribution': self.device_distribution(),
                'total': self.device_total(),
                'ip_distribution': self.assets_ip(),
                'risk_top_five': self.risk_device_top_five(),
                'external_ip_top_five': self.external_ip_top_five(),
            }
        }
        self.manual_send(message)

    def device_distribution(self):
        serializer = DeviceDistributionSerializer(Device.objects.all())
        return serializer.data

    def device_total(self):
        serializer = DeviceCountSerializer(Device.objects.all())
        return serializer.data

    def risk_device_top_five(self):
        serializer = RiskDeviceTopFiveSerializer(Device.objects.all())
        return serializer.data

    def assets_ip(self):
        serializer = AssetsIPSerializer(Device.objects.all())
        return serializer.data

    def external_ip_top_five(self):
        external = TodayExternalIP(self.current)
        data = external.get_top_n()
        serializer = ExternalIPTopSerializer(data)
        return serializer.data


class NetworkConsumer(StatisticNotification):
    """
    流量中心
    """
    room_group_name = 'network'
    current = None

    def initial_group(self):
        self.current = timezone.now()
        super().initial_group()

    def connect(self):
        super().connect()
        message = {
            'message': self.room_group_name,
            'data': {
                'port_top_five': self.port_top_five(),
                'ip_top_five': self.ip_top_five(),
            }
        }
        self.manual_send(message)

    def port_top_five(self):
        port = PortRank(self.current)
        data = port.get_top_n()
        serializer = PortRankSerializer(data)
        return serializer.data

    def ip_top_five(self):
        ip_rank = ProtocolIPRank(self.current)
        data = ip_rank.get_top_n()
        serializer = IPRankSerializer(data)
        return serializer.data


class LogCenterConsumer(StatisticNotification):
    """
    日志中心
    """
    room_group_name = 'log'
    current = None

    def initial_group(self):
        self.current = timezone.now()
        super().initial_group()

    def connect(self):
        super().connect()
        message = {
            'message': self.room_group_name,
            'data': {
                'total': self.log_statistic(),
                'day_trend': self.log_statistic_day(),
                'hour_trend': self.log_statistic_hour(),
                'collect_top_five': self.log_device_top_five(),
                'dst_ip_top_five': self.log_dst_ip_top_five(),
                'category_distribution': self.category_distribution(),
                'port_distribution': self.port_distribution(),
            }
        }
        self.manual_send(message)

    def log_statistic(self):
        serializer = LogStatisticTotalSerializer(LogStatistic.objects.first())
        return serializer.data

    def log_statistic_day(self):
        serializer = LogStatisticDaySerializer(
            LogStatisticDay.objects.order_by('-update_time')[:15][::-1])
        return serializer.data

    def log_statistic_hour(self):
        serializer = LogStatisticHourSerializer(
            LogStatistic.objects.all().order_by('-update_time')[:24][::-1])
        return serializer.data

    def log_device_top_five(self):
        instances = LogStatic.objects.all().order_by('-today')[:5]
        for instance in instances:
            if instances[0].today != 0:
                instance.percent = round(
                    instance.today / instances[0].today * 100)
            else:
                instance.percent = 0
        serializer = LogDeviceTopFiveSerializer(instances)
        return serializer.data

    def log_dst_ip_top_five(self):
        serializer = LogDstIPTopFiveSerializer(
            LogDstIPTopFive.objects.all().order_by('-update_time').first())
        return serializer.data

    def category_distribution(self):
        serializer = CategoryDistributionSerializer(
            LogCategoryDistribution.objects.all().order_by(
                '-update_time').first())
        return serializer.data

    def port_distribution(self):
        serializer = PortDistributionSerializer(
            LogPortDistribution.objects.all().order_by('-update_time').first())
        return serializer.data
