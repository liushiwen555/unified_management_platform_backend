from django.db.models import Q, F, Count
from django.utils import timezone
from django.utils.decorators import method_decorator
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from requests.exceptions import ConnectionError
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from auditor.bolean_auditor import AuditorNetwork, AuditorProtocolTraffics, \
    AuditorProtocolDistribution, AuditorDeviceTraffics
from auditor.bolean_auditor.process_protocol import TodayExternalIP, PortRank, \
    ProtocolIPRank, IPSource, AttackIPRank, IPQueueProcess
from auditor.models import RiskCountry, AttackIPStatistic
from base_app.models import Device
from log.models import DeviceAllAlert, AlertDistribution, IncrementDistribution
from setting.models import Setting
from snmp.filters import SNMPDataFilter
from snmp.models import SNMPData
from snmp.serializers import SNMPDataSerializer
from statistic.filters import DeviceFilter
from statistic.models import MainView, LogCenter, \
    LogStatistic, LogStatisticDay, LogDstIPTopFive, \
    LogCategoryDistribution, LogPortDistribution, SystemRunning, AlertWeekTrend
from statistic.serializers import MainViewSerializer, AssetsCenterSerializer, \
    MonitorCenterSerializer, LogCenterSerializer, LogStatisticTotalSerializer, \
    LogStatisticDaySerializer, LogStatisticHourSerializer, \
    LogDeviceTopFiveSerializer, LogDstIPTopFiveSerializer, \
    CategoryDistributionSerializer, PortDistributionSerializer, \
    SystemRunningStatusSerializer, SystemBasicInfoSerializer, \
    UserDistributionSerializer, AlertProcessSerializer, AlertThreatSerializer, \
    NetworkTrafficSerializer, UnResolvedAlertSerializer, \
    DeviceDistributionSerializer, DeviceCountSerializer, \
    RiskDeviceTopFiveSerializer, AssetsIPSerializer, ProtocolSerializer, \
    ProtocolDistributionSerializer, DeviceTrafficSerializer, \
    ExternalIPTopSerializer, PortRankSerializer, IPRankSerializer, \
    IPMapSerializer, RiskSrcCountrySerializer, AttackStatisticSerializer, \
    DeviceAlertDistributionSerializer, DeviceAlertRealtimeSerializer, \
    IncrementTrendSerializer, AlertWeekTrendSerializer, \
    LockedUsernameSerializer, AbnormalLoginSerializer, \
    AbnormalBehaviorSerializer, AlertRealtimeSerializer, \
    AttackLocationSerializer, AlertIPRankSerializer
from unified_log.models import LogStatistic as LogStatic
from user.models import User, UserExtension
from utils.core.exceptions import CustomError
from utils.helper import get_today


class BaseView(GenericAPIView):
    """
    运营态势的接口几乎都不用分页和筛选
    """
    pagination_class = None
    filter_backends = []


class MainViewSet(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = MainViewSerializer
    queryset = MainView.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-主视图',
        responses={'200': openapi.Response('主视图内容', MainViewSerializer())}
    ))
    def get(self, request):
        instance = self.get_queryset().first()
        attack = IPSource(timezone.now())
        attack_data = attack.get_attack_data()
        attack_ip = AttackIPStatistic.objects.first()
        if attack_ip:
            instance.ip_count = attack_ip.external_ip + attack_data[
                'external_ip']
        serializer = self.get_serializer(instance)

        return Response(serializer.data)


class AssetsCenterView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AssetsCenterSerializer
    queryset = Device.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-资产中心',
        responses={'200': openapi.Response('资产中心内容', AssetsCenterSerializer())}
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset())

        return Response(serializer.data)


class MonitorCenterView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = MonitorCenterSerializer
    queryset = Device.objects.all()
    pagination_class = None
    filter_backends = None

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-性能中心',
        responses={'200': openapi.Response('性能中心内容', MonitorCenterSerializer())}
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset())

        return Response(serializer.data)


class LogCenterView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LogCenterSerializer
    queryset = LogCenter.objects.all().order_by('-update_time')
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-日志中心',
        responses={'200': openapi.Response('日志中心', LogCenterSerializer())}
    ))
    def get(self, request):
        instances = self.get_queryset()[:10]
        instances = instances[::-1]
        serializer = self.get_serializer(instances)
        return Response(serializer.data)


class SNMPDataView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = SNMPDataSerializer
    queryset = SNMPData.objects.filter(device__monitor=True)
    filter_class = SNMPDataFilter
    pagination_class = None

    @method_decorator(swagger_auto_schema(
        operation_summary='性能中心接口'
    ))
    def get(self, request):
        if not (request.query_params['name'] or request.query_params['ip']):
            serializer = self.get_serializer(None)
            return Response(serializer.data)
        device_filter = DeviceFilter(request.query_params,
                                     queryset=Device.objects.all())
        device = device_filter.qs
        if not device.exists():
            raise CustomError(error_code=CustomError.ASSET_NOT_FOUND)
        device = device[0]
        queryset = self.filter_queryset(self.get_queryset())
        instance = queryset.first()
        serializer = self.get_serializer(instance)
        data = serializer.data
        data.update({'name': device.name, 'ip': device.ip})
        return Response(data)


class LogStatisticView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LogStatisticTotalSerializer
    queryset = LogStatistic.objects.all()
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-日志中心',
        operation_description='本地日志累计，采集日志累计, 今日增加，总共所有',
        responses={'200': openapi.Response('性能中心内容',
                                           LogStatisticTotalSerializer())}
    ))
    def get(self, request):
        instance = self.get_queryset().first()
        serializer = self.get_serializer(instance)

        return Response(serializer.data)


class LogStatisticDayView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LogStatisticDaySerializer
    queryset = LogStatisticDay.objects.all().order_by('-update_time')
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-日志中心-本地和采集日志按日的趋势图',
        responses={'200': openapi.Response('日志按日的趋势',
                                           LogStatisticDaySerializer())}
    ))
    def get(self, request):
        instances = self.get_queryset()[:15]
        instances = instances[::-1]
        serializer = self.get_serializer(instances)
        return Response(serializer.data)


class LogStatisticHourView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LogStatisticHourSerializer
    queryset = LogStatistic.objects.all().order_by('-update_time')
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-日志中心-24小时内的采集日志趋势',
        responses={'200': openapi.Response('日志按小时的趋势',
                                           LogStatisticHourSerializer())}
    ))
    def get(self, request):
        instances = self.get_queryset()[:24]
        instances = instances[::-1]
        serializer = self.get_serializer(instances)
        return Response(serializer.data)


class LogDeviceTopFiveView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LogDeviceTopFiveSerializer
    queryset = LogStatic.objects.all().order_by('-today')
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-日志中心-采集量今日最高的5个资产',
        responses={'200': openapi.Response('采集量今日最高的5个资产',
                                           LogDeviceTopFiveSerializer())}
    ))
    def get(self, request):
        instances = self.get_queryset()[:5]
        for instance in instances:
            if instances[0].today != 0:
                instance.percent = round(
                    instance.today / instances[0].today * 100)
            else:
                instance.percent = 0
        serializer = self.get_serializer(instances)
        return Response(serializer.data)


class LogDstIPTopFiveView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LogDstIPTopFiveSerializer
    queryset = LogDstIPTopFive.objects.all().order_by('-update_time')
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-日志中心-目的IP采集量的5个IP',
        responses={'200': openapi.Response('目的IP采集量的5个IP',
                                           LogDstIPTopFiveSerializer(
                                               many=True))}
    ))
    def get(self, request):
        instance = self.get_queryset().first()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class CategoryDistributionViews(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = CategoryDistributionSerializer
    queryset = LogCategoryDistribution.objects.all().order_by('-update_time')
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-日志中心-按资产类型划分',
        responses={'200': openapi.Response('按资产类型划分',
                                           CategoryDistributionSerializer())}
    ))
    def get(self, request):
        instances = self.get_queryset().first()
        serializer = self.get_serializer(instances)
        return Response(serializer.data)


class PortDistributionViews(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PortDistributionSerializer
    queryset = LogPortDistribution.objects.all().order_by('-update_time')
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='运营态势-日志中心-端口',
        responses={'200': openapi.Response('端口', PortDistributionSerializer())}
    ))
    def get(self, request):
        instances = self.get_queryset().first()
        serializer = self.get_serializer(instances)
        return Response(serializer.data)


class SystemRunningView(GenericAPIView):
    """
    设备运行状态
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = SystemRunningStatusSerializer
    queryset = SystemRunning.objects.all()
    pagination_class = None
    filter_backends = []

    def get(self, request):
        instance = self.get_queryset().first()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class SystemInfoView(GenericAPIView):
    """
    设备基本信息
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = SystemBasicInfoSerializer
    queryset = Setting.objects.all()
    pagination_class = None
    filter_backends = []

    def get(self, request):
        serializer = self.get_serializer(self.get_queryset().first())
        return Response(serializer.data)


class UserDistributionView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = UserDistributionSerializer
    queryset = User.objects.all()
    pagination_class = None
    filter_backends = []

    def get(self, request):
        serializer = self.get_serializer(self.get_queryset())
        return Response(serializer.data)


class AlertProcessView(GenericAPIView):
    """
    待处理安全告警（安全事件+安全威胁）
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = AlertProcessSerializer
    queryset = DeviceAllAlert.objects.all()
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='告警处理的百分比',
        responses={'200': openapi.Response('结果', AlertProcessSerializer())}
    ))
    def get(self, request):
        serializer = self.get_serializer(DeviceAllAlert())

        return Response(serializer.data)


class AlertThreatView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AlertThreatSerializer
    queryset = DeviceAllAlert.objects.filter().order_by('-occurred_time')
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='实时威胁监控',
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset()[:7], many=True)

        return Response(serializer.data)


class NetworkTrafficView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = NetworkTrafficSerializer
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='流量中心'
    ))
    def get(self, request):
        auditor = Device.objects.filter(type=Device.AUDITOR,
                                        register_status=Device.REGISTERED)
        if not auditor.exists():
            return Response(self.get_serializer([]).data)
        auditor = auditor[0]
        network = AuditorNetwork(auditor)
        try:
            response = network.request_for_data()
        except ConnectionError:
            response = []
        # response = [{"time":"2020-12-08T15:42:40.948706+08:00","nic_infos":[{"nic_name":"MGMT","traffic_rate":240.0},{"nic_name":"LAN1","traffic_rate":0.0},{"nic_name":"LAN2","traffic_rate":0.0},{"nic_name":"LAN3","traffic_rate":0.0},{"nic_name":"LAN4","traffic_rate":0.0},{"nic_name":"LAN5","traffic_rate":0.0}]},{"time":"2020-12-08T15:42:45.948706+08:00","nic_infos":[{"nic_name":"MGMT","traffic_rate":380.0},{"nic_name":"LAN1","traffic_rate":0.0},{"nic_name":"LAN2","traffic_rate":0.0},{"nic_name":"LAN3","traffic_rate":0.0},{"nic_name":"LAN4","traffic_rate":0.0},{"nic_name":"LAN5","traffic_rate":0.0}]},{"time":"2020-12-08T15:42:50.948706+08:00","nic_infos":[{"nic_name":"MGMT","traffic_rate":20174.0},{"nic_name":"LAN1","traffic_rate":0.0},{"nic_name":"LAN2","traffic_rate":0.0},{"nic_name":"LAN3","traffic_rate":0.0},{"nic_name":"LAN4","traffic_rate":0.0},{"nic_name":"LAN5","traffic_rate":0.0}]}]
        data = self.get_serializer(response[-8:]).data
        return Response(data)


class ProtocolTrafficView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProtocolSerializer
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='实时协议分布'
    ))
    def get(self, request):
        auditor = Device.objects.filter(type=Device.AUDITOR,
                                        register_status=Device.REGISTERED)
        if not auditor.exists():
            return Response(self.get_serializer([]).data)
        auditor = auditor[0]
        protocol = AuditorProtocolTraffics(auditor)
        try:
            response = protocol.request_for_data()
        # response = [
        #     {'proto_traffics': [{'protocol': 'CIP', 'traffic_rate': 0.0}],
        #      'time': '2020-12-17T13:43:27.337868+08:00'},
        #     {'proto_traffics': [{'protocol': 'CIP', 'traffic_rate': 0.0}],
        #      'time': '2020-12-17T13:43:32.337868+08:00'}, ]
        except ConnectionError:
            response = []
        data = self.get_serializer(response[-48:]).data
        return Response(data)


class ProtocolDistributionView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProtocolDistributionSerializer
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='协议类型统计'
    ))
    def get(self, request):
        auditor = Device.objects.filter(type=Device.AUDITOR,
                                        register_status=Device.REGISTERED)
        if not auditor.exists():
            return Response(self.get_serializer([]).data)
        auditor = auditor[0]
        protocol = AuditorProtocolDistribution(auditor)
        try:
            response = protocol.request_for_data()
        # from auditor.tests.data import protocol_distribution
        # response = protocol_distribution
        except ConnectionError:
            response = []
        data = self.get_serializer(response).data
        return Response(data)


class DeviceTrafficView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = DeviceTrafficSerializer
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='实时资产流量'
    ))
    def get(self, request):
        auditor = Device.objects.filter(type=Device.AUDITOR,
                                        register_status=Device.REGISTERED)
        if not auditor.exists():
            return Response(self.get_serializer([]).data)
        auditor = auditor[0]
        protocol = AuditorDeviceTraffics(auditor)
        try:
            response = protocol.request_for_data()
        # from auditor.tests.data import device_traffics
        # response = device_traffics
        except ConnectionError:
            response = []
        data = self.get_serializer(response[-48:]).data
        return Response(data)


class UnResolvedAlertView(GenericAPIView):
    """
    未处理告警
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = UnResolvedAlertSerializer
    pagination_class = None
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='未处理安全威胁',
        responses={'200': openapi.Response('数量', UnResolvedAlertSerializer())}
    ))
    def get(self, request):
        alert = DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()

        return Response({'data': alert})


class DeviceDistributionView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = DeviceDistributionSerializer
    pagination_class = None
    filter_backends = None
    queryset = Device.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='分类统计资产信息',
        responses={'200': openapi.Response('资产统计',
                                           DeviceDistributionSerializer())}
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset())
        data = serializer.data
        return Response(data)


class DeviceTotalView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = DeviceCountSerializer
    pagination_class = None
    filter_backends = None
    queryset = Device.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='资产总数',
        responses={'200': openapi.Response('资产总数',
                                           DeviceCountSerializer())}
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset())

        return Response(serializer.data)


class RiskDeviceTopFiveView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = RiskDeviceTopFiveSerializer
    pagination_class = None
    filter_backends = None
    queryset = Device.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='风险资产Top5',
        responses={'200': openapi.Response('已经按照顺序排好的Top5资产',
                                           RiskDeviceTopFiveSerializer())}
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset())

        return Response(serializer.data)


class AssetsIPView(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AssetsIPSerializer
    pagination_class = None
    filter_backends = None
    queryset = Device.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='资产IP使用情况',
        responses={'200': openapi.Response('IP使用情况', AssetsIPSerializer())}
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset())

        return Response(serializer.data)


class ExternalIPTopFiveView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ExternalIPTopSerializer

    @method_decorator(swagger_auto_schema(
        operation_summary='外联资产TOP5',
    ))
    def get(self, request):
        external = TodayExternalIP(timezone.now())
        data = external.get_top_n()
        serializer = self.get_serializer(data)

        return Response(serializer.data)


class PortTopFiveView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = PortRankSerializer

    @method_decorator(swagger_auto_schema(
        operation_summary='流量中心——今日端口排名'
    ))
    def get(self, request):
        port = PortRank(timezone.now())
        data = port.get_top_n()
        serializer = self.get_serializer(data)

        return Response(serializer.data)


class IPTopFiveView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = IPRankSerializer

    @method_decorator(swagger_auto_schema(
        operation_summary='流量中心——今日IP排名'
    ))
    def get(self, request):
        ip_rank = ProtocolIPRank(timezone.now())
        data = ip_rank.get_top_n()
        serializer = self.get_serializer(data)

        return Response(serializer.data)


class IPMapView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = IPMapSerializer

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势中心——IP地图',
    ))
    def get(self, request):
        ip_source = IPSource(timezone.now())
        data = ip_source.get_city_data()
        serializer = self.get_serializer(data)

        return Response(serializer.data)


class RiskCountryTopFiveView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = RiskSrcCountrySerializer
    queryset = RiskCountry.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势中心——威胁源地图top5'
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset()[:5])
        return Response(serializer.data)


class AttackStatisticView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AttackStatisticSerializer

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势中心——安全统计'
    ))
    def get(self, request):
        attack = IPSource(timezone.now())
        serializer = self.get_serializer(attack.get_attack_data())
        return Response(serializer.data)


class DeviceAlertDistributionView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = DeviceAlertDistributionSerializer
    queryset = AlertDistribution.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势中心——威胁分布'
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset().first())

        return Response(serializer.data)


class DeviceAlertRealtimeView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = DeviceAlertRealtimeSerializer
    queryset = DeviceAllAlert.objects.all().order_by('-occurred_time')

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势中心——攻击时序图'
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset())
        return Response(serializer.data)


class AlertTrendView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = IncrementTrendSerializer
    queryset = IncrementDistribution.objects.all().order_by('-update_time')

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势中心——安全威胁趋势'
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset()[:48])
        return Response(serializer.data)


class AlertWeekTrendView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AlertWeekTrendSerializer
    queryset = AlertWeekTrend.objects.all().order_by('-id')

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势——异常行为——安全威胁每周趋势',
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset()[:7])

        return Response(serializer.data)


class LockedUserView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = LockedUsernameSerializer
    queryset = UserExtension.objects.filter(banned=True).order_by(
        '-last_failure')

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势——异常行为——锁定账号'
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset()[:5], many=True)

        return Response(serializer.data)


class AbnormalLoginView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AbnormalLoginSerializer
    # 22点-6点异常登录
    queryset = UserExtension.abnormal_login()

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势——异常行为——异常登录'
    ))
    def get(self, request):
        serializer = self.get_serializer(self.get_queryset()[:5], many=True)

        return Response(serializer.data)


class AbnormalBehaviorView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AbnormalBehaviorSerializer
    queryset = UserExtension.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势——异常行为——锁定账号、异常登录、外网方位IP、境外访问IP'
    ))
    def get(self, request):
        serializer = self.get_serializer(
            {'instance': self.get_queryset(),
             'ip_queue': IPQueueProcess(timezone.now())})

        return Response(serializer.data)


class AttackIPRankView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = IPRankSerializer

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势——攻击画像——今日攻击源TOP5和目的TOP5'
    ))
    def get(self, request):
        attack = AttackIPRank(timezone.now()).get_top_n()

        return Response(attack)


class AlertRealtimeView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AlertRealtimeSerializer
    queryset = DeviceAllAlert.objects.all().order_by('-occurred_time')

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势——攻击画像——今日实时威胁'
    ))
    def get(self, request):
        queryset = self.get_queryset().filter(
            occurred_time__gte=get_today(timezone.now()))
        serializer = self.get_serializer(queryset)

        return Response(serializer.data)


class AttackLocationView(BaseView):
    permission_classes = (IsAuthenticated,)
    serializer_class = AttackLocationSerializer
    queryset = DeviceAllAlert.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势——攻击画像——今日被攻击资产位置TOP5'
    ))
    def get(self, request):
        queryset = self.get_queryset().filter(
            occurred_time__gte=get_today(timezone.now())).values(
            'device__location').annotate(count=Count('id')).annotate(
            location=F('device__location')).order_by('-count')
        data = [i for i in queryset if i['location']]
        serializer = self.get_serializer(data=data[:5], many=True)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data)


class AlertIPRankView(BaseView):
    """
    统计最新的威胁，分为外部和内部威胁，然后对每一条的IP统计今日的威胁数量
    """
    permission_classes = (IsAuthenticated,)
    serializer_class = AlertIPRankSerializer
    queryset = DeviceAllAlert.objects.all().order_by('-occurred_time')

    @method_decorator(swagger_auto_schema(
        operation_summary='安全态势——攻击画像——今日内部、外部威胁'
    ))
    def get(self, request):
        queryset = self.get_queryset().filter(
            occurred_time__gte=get_today(timezone.now()))
        serializer = self.get_serializer(queryset)

        return Response(serializer.data)


from django.shortcuts import render


def room(request):
    return render(request, 'room.html', {})
