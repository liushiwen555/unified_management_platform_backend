import datetime

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.encoding import escape_uri_path
from django_filters.rest_framework import DjangoFilterBackend
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.filters import OrderingFilter
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import CreateModelMixin, ListModelMixin, \
    DestroyModelMixin, RetrieveModelMixin
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet, ReadOnlyModelViewSet

from auditor.bolean_auditor.synchronize import AuditorProtocolInterface
from auditor.filters import AuditLogFilter
from auditor.models import AuditLog, AuditSysAlert
from auditor.serializers import AuditLogSerializer
from base_app.models import Device, EventLog
from base_app.serializers import EventLogSerializer
from firewall.filters import FirewallSysEventFilter
from firewall.models import FirewallSysEvent
from firewall.serializers import FirewallSysEventSerializer
from log.filters import ServerRunLogFilter, TerminalDevInstallationLogFilter, \
    TerminalDevRunLogFilter, StrategyDistributionStatusLogFilter, \
    AllDeviceAlertFilter, UnifiedForumLogFilter, SecurityEventFilter
from log.models import ServerRunLog, TerminalInstallationLog, TerminalRunLog, \
    StrategyDistributionStatusLog, DeviceAllAlert, UnifiedForumLog, ReportLog, \
    SecurityEvent
from log.serializers import ServerRunLogSerializer, \
    TerminalDevInstallationLogSerializer, TerminalDevRunLogSerializer, \
    StrategyDistributionStatusLogSerializer, DeviceAllAlertSerializer, \
    DeviceAlertResolveSerialzier, BatchDeviceAlertSerialzier, \
    UnifiedForumLogSerializer, \
    ReportGenerateSerializer, ReportLogDetailSerializer, ReportLogSerializer, \
    DeviceAllAlertDetailSerializer, DeviceAlertFilterSerializer, \
    ResolveDeviceAlertSerializer, SecurityEventListSerializer, \
    SecurityEventDetailSerializer, SecurityEventFilterSerializer, \
    StatisticInfoSerializer, AuditorProtocolQuerySerializer, \
    AuditorProtocolSerializer
from utils.core.exceptions import CustomError
from utils.core.mixins import \
    ConfiEngineerPermissionsMixin as EngineerPermissionsMixin
from utils.core.mixins import MultiActionConfViewSetMixin
from utils.core.permissions import IsSecurityEngineer, IsConfiEngineer
from utils.core.renders import ExportDOCXRenderer

User = get_user_model()


class BaseLogView(ReadOnlyModelViewSet):
    permission_classes = (IsConfiEngineer,)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance.is_read:
            instance.is_read = True
            instance.read_time = timezone.now()
            instance.save()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class UnifiedForumLogView(BaseLogView):
    """
    custom_swagger: 自定义 api 接口文档
    get:
      request:
        description: 本机日志列表，即综管本身终端日志列表，有 id 为日志详情，无 id 为日志列表
    """

    queryset = UnifiedForumLog.objects.all()
    serializer_class = UnifiedForumLogSerializer
    filter_class = UnifiedForumLogFilter
    permission_classes = (IsConfiEngineer,)
    ordering_fields = ('occurred_time', 'id')

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        category = self.request.query_params.get('category')
        type_ = self.request.query_params.get('type')

        if category == str(UnifiedForumLog.CATEGORY_OPERATION):
            queryset = queryset.filter(
                category=UnifiedForumLog.CATEGORY_OPERATION,
                type__in=UnifiedForumLog.OPERATOR_TYPE)
        if category == str(UnifiedForumLog.CATEGORY_USER_MANAGEMENT):
            queryset = queryset.filter(
                category=UnifiedForumLog.CATEGORY_USER_MANAGEMENT,
                type__in=UnifiedForumLog.USER_MANAGEMENT_TYPE)
        if category == str(UnifiedForumLog.CATEGORY_LOGIN_LOGOUT):
            queryset = queryset.filter(
                category=UnifiedForumLog.CATEGORY_LOGIN_LOGOUT,
                type__in=UnifiedForumLog.LOGIN_LOGOUT_TYPE)
        if category == str(UnifiedForumLog.CATEGORY_SYSTEM):
            queryset = queryset.filter(
                category=UnifiedForumLog.CATEGORY_SYSTEM,
                type__in=UnifiedForumLog.SYSTEM_TYPE,
            )

        if type_ in [str(i) for i in UnifiedForumLog.OPERATOR_TYPE]:
            queryset = queryset.filter(
                category=UnifiedForumLog.CATEGORY_OPERATION)

        if type_ in [str(i) for i in UnifiedForumLog.USER_MANAGEMENT_TYPE]:
            queryset = queryset.filter(
                category=UnifiedForumLog.CATEGORY_USER_MANAGEMENT)

        if type_ in [str(i) for i in UnifiedForumLog.LOGIN_LOGOUT_TYPE]:
            queryset = queryset.filter(
                category=UnifiedForumLog.CATEGORY_LOGIN_LOGOUT)

        if type_ in [str(i) for i in UnifiedForumLog.SYSTEM_TYPE]:
            queryset = queryset.filter(
                category=UnifiedForumLog.CATEGORY_SYSTEM,
            )

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class ServerRunLogView(BaseLogView):
    queryset = ServerRunLog.objects.all()
    serializer_class = ServerRunLogSerializer
    filter_class = ServerRunLogFilter
    permission_classes = (IsConfiEngineer,)


class TerminalDevInstallationLogView(BaseLogView):
    queryset = TerminalInstallationLog.objects.all()
    serializer_class = TerminalDevInstallationLogSerializer
    filter_class = TerminalDevInstallationLogFilter
    permission_classes = (IsConfiEngineer,)


class TerminalDevRunLogView(BaseLogView):
    queryset = TerminalRunLog.objects.all()
    serializer_class = TerminalDevRunLogSerializer
    filter_class = TerminalDevRunLogFilter
    permission_classes = (IsConfiEngineer,)


class StrategyDistributionStatusLogView(BaseLogView):
    queryset = StrategyDistributionStatusLog.objects.all()
    serializer_class = StrategyDistributionStatusLogSerializer
    filter_class = StrategyDistributionStatusLogFilter
    permission_classes = (IsConfiEngineer,)


class AuditLogView(BaseLogView):
    """
    custom_swagger: 自定义 api 接口文档
    get:
      request:
        description: 审计终端日志列表，有 id 日志详情，无 id 日志列表
    """
    permission_classes = (IsConfiEngineer,)
    queryset = AuditSysAlert.objects.all()
    serializer_class = AuditLogSerializer
    filter_class = AuditLogFilter
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    ordering_fields = ('occurred_time',)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


#
# class AuditLogView(BaseLogView):
#     """
#     custom_swagger: 自定义 api 接口文档
#     get:
#       request:
#         description: 审计终端日志列表，有 id 日志详情，无 id 日志列表
#     """
#     permission_classes = (IsConfiEngineer, )
#     queryset = AuditLog.objects.all()
#     serializer_class = AuditLogSerializer
#     filter_class = AuditLogFilter
#     search_fields = ('id', 'ip', 'device__name')


class FirewallSysEventView(BaseLogView):
    """
    custom_swagger: 自定义 api 接口文档
    get:
      request:
        description: 防火墙终端日志, 有 id 日志详情，无 id 日志列表
    """
    queryset = FirewallSysEvent.objects.all()
    serializer_class = FirewallSysEventSerializer
    filter_class = FirewallSysEventFilter
    permission_classes = (IsConfiEngineer,)
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    ordering_fields = ('occurred_time',)


# 这是知识库的内容
class EventLogView(ListModelMixin,
                   EngineerPermissionsMixin,
                   GenericViewSet):
    """
    custom_swagger: 自定义 api 接口文档
    get:
      request:
        description: 知识库列表，内置，不可修改
    """

    queryset = EventLog.objects.all()
    serializer_class = EventLogSerializer
    serializer_action_classes = {
        'list': EventLogSerializer,
    }
    permission_classes = (IsConfiEngineer,)

    search_fields = ('id', 'name')
    ordering_fields = ('id',)
    filter_fields = ('category', 'type', 'level')

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        category = self.request.query_params.get('category')
        type_ = self.request.query_params.get('type')

        if category == '1':
            queryset = queryset.filter(category=1, type__in=[1, 2, 3, 4, 5, 30])
        if category == '2':
            queryset = queryset.filter(category=2, type__in=[6])
        if category == '3':
            queryset = queryset.filter(category=3, type__in=[7, 8, 9, 10])
        if category == '4':
            queryset = queryset.filter(category=4, type__in=[11, 12])

        if type_ in ['1', '2', '3', '4', '5', '30']:
            queryset = queryset.filter(category=1)

        if type_ == ['6']:
            queryset = queryset.filter(category=2)

        if type_ in ['9', '10', '7', '8']:
            queryset = queryset.filter(category=3)

        if type_ in ['12', '11']:
            queryset = queryset.filter(category=4)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class DeviceAllAlertView(MultiActionConfViewSetMixin, BaseLogView):
    queryset = DeviceAllAlert.objects.all()
    serializer_class = DeviceAllAlertSerializer
    filter_fields = ('level', 'type', 'status_resolved', 'category')
    filter_class = AllDeviceAlertFilter
    permission_classes = (IsConfiEngineer,)
    serializer_action_classes = {
        'list': DeviceAllAlertSerializer,
        'retrieve': DeviceAllAlertDetailSerializer,
        'resolve': DeviceAlertResolveSerialzier,
        'batch_resolve': BatchDeviceAlertSerialzier,
        'last_24_hours': DeviceAllAlertSerializer,
        'statistic_info': StatisticInfoSerializer,
    }
    filter_backends = [DjangoFilterBackend]

    def list(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 所有告警信息, 这里后续需要等审计告警信息补充
        """
        queryset = self.filter_queryset(self.get_queryset())

        queryset = queryset.order_by('-id')

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.paginator.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(methods=['get'], detail=False, permission_classes=(IsSecurityEngineer,),
                filter_backends=[], pagination_class=None)
    def statistic_info(self, request, **kwargs):
        all_count = DeviceAllAlert.objects.count()
        unresolved_count = DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()

        last_alert_time = ''

        if DeviceAllAlert.objects.count() > 0:
            last_alert_time = DeviceAllAlert.objects.latest(
                'occurred_time').occurred_time

        d = dict(
            all_count=all_count,
            unresolved_count=unresolved_count,
            last_alert_time=last_alert_time
        )

        return Response(d)

    @action(methods=['get'], detail=False, permission_classes=(IsSecurityEngineer,))
    def last_24_hours(self, request):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description:  get 方法，过往 24 小时内告警信息
        """
        end_time = timezone.now()
        start_time = end_time - datetime.timedelta(days=1)
        device_alerts = DeviceAllAlert.objects.filter(first_at__lte=end_time,
                                                      first_at__gte=start_time)
        data = DeviceAllAlertSerializer(device_alerts, many=True).data
        return Response(data)


class ResolveAlertView(GenericAPIView):
    serializer_class = ResolveDeviceAlertSerializer
    queryset = DeviceAllAlert.objects.all()
    permission_classes = (IsSecurityEngineer,)
    filter_backends = []

    @method_decorator(swagger_auto_schema(
        operation_summary='单独处理某条告警',
    ))
    def put(self, request, pk):
        serializer = DeviceAlertResolveSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        des_resolved = serializer.validated_data.get('des_resolved')
        status_resolved = serializer.validated_data.get('status_resolved')
        user = request.user
        time_resolved = timezone.localtime()

        device_alert = self.get_object()
        if device_alert.status_resolved == DeviceAllAlert.STATUS_RESOLVED:
            raise CustomError(error_code=CustomError.DEVICE_ALLERT_ERROR)
        device_alert.user = user
        device_alert.time_resolved = time_resolved
        device_alert.des_resolved = des_resolved
        device_alert.status_resolved = status_resolved
        device_alert.save()
        return Response(status=status.HTTP_200_OK)


class ResolveAllAlertView(GenericAPIView):
    serializer_class = ResolveDeviceAlertSerializer
    queryset = DeviceAllAlert.objects.all()
    permission_classes = (IsSecurityEngineer,)
    filter_class = AllDeviceAlertFilter
    filter_backends = [DjangoFilterBackend]
    model = DeviceAllAlert
    message = '每次处理上限为1000，本次已处理了1000条安全威胁'

    @method_decorator(swagger_auto_schema(
        query_serializer=DeviceAlertFilterSerializer(),
        operation_summary='批量处理筛选条件下的告警',
        operation_description='最多处理1000条安全威胁，超过1000条只处理前1000条，并'
                              '在响应的detail字段提示'
    ))
    def put(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        user = request.user

        error = False
        first_id = ''
        count = 0
        message = ''
        with transaction.atomic():
            try:
                first_id, count, message = self.resolve(data, user)
            except Exception:
                error = True

        if error:
            raise CustomError(error_code=CustomError.DEVICE_ALLERT_ERROR)

        data.update({'first_id': first_id, 'count': count, 'detail': message})
        return Response(data)

    def resolve(self, data, user):
        time = timezone.localtime()
        queryset = self.filter_queryset(self.get_queryset()).filter(
            status_resolved=self.model.STATUS_UNRESOLVED)
        count = queryset.count()
        message = ''
        if count > 1000:
            first_thousand = queryset[:1000]
            queryset = queryset.filter(id__in=[i.id for i in first_thousand])
            message = self.message
        # 记录下id和修改的数量用于日志的记录
        first = queryset.first()
        first_id = first.id if first else ''
        count = queryset.count()
        with transaction.atomic():
            queryset.update(status_resolved=data['status_resolved'],
                            des_resolved=data['des_resolved'],
                            user=user, time_resolved=time)

        return first_id, count, message


class BatchResolveAlertView(GenericAPIView):
    serializer_class = BatchDeviceAlertSerialzier
    queryset = DeviceAllAlert.objects.all()
    permission_classes = (IsSecurityEngineer,)
    filter_backends = []
    model = DeviceAllAlert
    message = '每次处理上限为1000，本次已处理了1000条安全威胁'

    @method_decorator(swagger_auto_schema(
        operation_summary='传递id列表批量处理告警',
        operation_description='最多处理1000条安全威胁，超过1000条只处理前1000条，并'
                              '在响应的detail字段提示'
    ))
    def put(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        user = request.user

        error = False
        message = ''
        if data['ids']:
            try:
                with transaction.atomic():
                    message = self.resolve(data, user)
            except Exception:
                error = True
        if error:
            raise CustomError(error_code=CustomError.DEVICE_ALLERT_ERROR)
        data.update({'detail': message})
        return Response(data)

    def resolve(self, data, user):
        time = timezone.localtime()
        queryset = self.get_queryset().filter(
            id__in=data['ids'], status_resolved=self.model.STATUS_UNRESOLVED)
        count = queryset.count()
        message = ''
        if count > 1000:
            first_thousand = queryset[:1000]
            queryset = queryset.filter(id__in=[i.id for i in first_thousand])
            message = self.message
        # 记录下id和修改的数量用于日志的记录
        with transaction.atomic():
            queryset.update(status_resolved=data['status_resolved'],
                            des_resolved=data['des_resolved'],
                            user=user, time_resolved=time)

        return message


class ReportLogView(CreateModelMixin,
                    ListModelMixin,
                    DestroyModelMixin,
                    EngineerPermissionsMixin,
                    GenericViewSet):
    queryset = ReportLog.objects.all()
    serializer_class = ReportLogSerializer
    permission_classes = (IsSecurityEngineer,)

    serializer_action_classes = {
        'list': ReportLogSerializer,
        'create': ReportGenerateSerializer,
    }

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.data
        s_time = data.get('start_time')
        e_time = data.get('end_time')
        # c category  ac alert_count unres unresolved
        c_auditor = DeviceAllAlert.CATEGORY_APT
        c_firewall = DeviceAllAlert.CATEGORY_PENETRATION
        c_sys = DeviceAllAlert.CATEGORY_FLAW
        c_asset = DeviceAllAlert.CATEGORY_SCAN
        s_unres = DeviceAllAlert.STATUS_UNRESOLVED

        d_alert = DeviceAllAlert.objects.all()
        d_alert_in_time = d_alert.filter(occurred_time__lt=e_time,
                                         occurred_time__gte=s_time)

        ac = d_alert_in_time.count()
        auditor_ac = d_alert_in_time.filter(category=c_auditor).count()
        firewall_ac = d_alert_in_time.filter(category=c_firewall).count()
        sys_ac = d_alert_in_time.filter(category=c_sys).count()
        device_ac = d_alert_in_time.filter(category=c_asset).count()
        ac_unres = d_alert_in_time.filter(status_resolved=s_unres).count()
        auditor_ac_unres = d_alert_in_time.filter(category=c_auditor,
                                                  status_resolved=s_unres).count()
        firewall_ac_unres = d_alert_in_time.filter(category=c_firewall,
                                                   status_resolved=s_unres).count()
        sys_ac_unres = d_alert_in_time.filter(category=c_sys,
                                              status_resolved=s_unres).count()
        device_ac_unres = d_alert_in_time.filter(category=c_asset,
                                                 status_resolved=s_unres).count()

        ac_per = 100 if ac_unres == 0 or ac == 0 else 100 - round(
            100 * ac_unres / ac)
        auditor_ac_per = 100 if auditor_ac_unres == 0 or auditor_ac == 0 else 100 - round(
            100 * auditor_ac_unres / auditor_ac)
        firewall_ac_per = 100 if firewall_ac_unres == 0 or firewall_ac == 0 else 100 - round(
            100 * firewall_ac_unres / firewall_ac)
        sys_ac_per = 100 if sys_ac_unres == 0 or sys_ac == 0 else 100 - round(
            100 * sys_ac_unres / sys_ac)
        device_ac_per = 100 if device_ac_unres == 0 or device_ac == 0 else 100 - round(
            100 * device_ac_unres / device_ac)

        log_unified = UnifiedForumLog.objects.count()
        log_auditor = AuditLog.objects.count()
        log_firewall = FirewallSysEvent.objects.count()
        user_count = User.objects.filter(last_login__lt=e_time,
                                         last_login__gt=s_time).count()

        ds = Device.objects.filter(created_at__lt=e_time, created_at__gt=s_time)
        sec_ds_add = ds.filter(category=Device.CATEGORY_Security).count()
        com_ds_add = ds.filter(category=Device.CATEGORY_Communication).count()
        ser_ds_add = ds.filter(category=Device.CATEGORY_Sever).count()
        con_ds_add = ds.filter(category=Device.CATEGORY_Control).count()

        d = dict(
            alert_count=ac,
            auditor_alert_count=auditor_ac,
            firewall_alert_count=firewall_ac,
            sys_alert_count=sys_ac,
            device_alert_count=device_ac,
            alert_per=ac_per,
            auditor_alert_per=auditor_ac_per,
            firewall_alert_per=firewall_ac_per,
            sys_alert_per=sys_ac_per,
            device_alert_per=device_ac_per,
            unified_log_count=log_unified,
            auditor_log_count=log_auditor,
            firewall_log_count=log_firewall,
            login_account_count=user_count,
            sec_device_add=sec_ds_add,
            com_device_add=com_ds_add,
            ser_device_add=ser_ds_add,
            con_device_add=con_ds_add,
            start_time=s_time,
            end_time=e_time,
        )
        report = ReportLog.objects.create(**d)
        data.update(d)
        data.update({'id': report.id})  # 用于记录日志

        return Response(data, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description:  报表中心列表
        """
        return super(ReportLogView, self).list(request, *args, **kwargs)


class ExportReportLogView(APIView):
    permission_classes = [IsSecurityEngineer]
    renderer_classes = [ExportDOCXRenderer, JSONRenderer]

    def get(self, request, pk):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description:  报表下载
          response:
            200:
              description: '200'
        """
        ins = ReportLog.objects.get(pk=pk)
        serializer = ReportLogDetailSerializer(ins)
        data = serializer.data

        response = Response(data=data)
        filename = '报表下载{time}.{format}'.format(
            time=timezone.now().strftime('%Y%m%d %H%M%S'),
            format='docx'
        )
        response[
            'Content-Disposition'] = "attachment; filename*=utf-8''{filename}".format(
            filename=escape_uri_path(filename))
        return response


class SecurityEventView(MultiActionConfViewSetMixin,
                        RetrieveModelMixin,
                        ListModelMixin,
                        GenericViewSet):
    permission_classes = (IsSecurityEngineer,)
    serializer_class = SecurityEventListSerializer
    queryset = SecurityEvent.objects.all()
    filter_class = SecurityEventFilter
    serializer_action_classes = {
        'list': SecurityEventListSerializer,
        'retrieve': SecurityEventDetailSerializer,
        'last_24_hours': SecurityEventListSerializer,
        'statistic_info': StatisticInfoSerializer,
    }

    @action(methods=['get'], detail=False, permission_classes=(IsSecurityEngineer,))
    def last_24_hours(self, request):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description:  get 方法，过往 24 小时内告警信息
        """
        end_time = timezone.now()
        start_time = end_time - datetime.timedelta(days=1)
        events = self.get_queryset().filter(
            occurred_time__lte=end_time, occurred_time__gte=start_time)
        data = self.get_serializer(events, many=True).data
        return Response(data)

    @action(methods=['get'], detail=False, permission_classes=(IsSecurityEngineer,),
                filter_backends=[], pagination_class=None)
    def statistic_info(self, request, **kwargs):
        all_count = self.get_queryset().count()
        unresolved_count = self.get_queryset().filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()

        last_alert_time = ''

        if all_count > 0:
            last_alert_time = self.get_queryset().latest(
                'occurred_time').occurred_time

        d = dict(
            all_count=all_count,
            unresolved_count=unresolved_count,
            last_alert_time=last_alert_time
        )

        return Response(d)


class ResolveSecurityView(ResolveAlertView):
    queryset = SecurityEvent.objects.all()

    @method_decorator(swagger_auto_schema(
        operation_summary='单独处理某条事件'
    ))
    def put(self, request, pk):
        return super().put(request, pk)


class BatchResolveSecurityView(BatchResolveAlertView):
    queryset = SecurityEvent.objects.all()
    model = SecurityEvent
    message = '每次处理上限为1000，本次已处理了1000条安全事件'

    @method_decorator(swagger_auto_schema(
        operation_summary='传递id列表批量处理事件',
        operation_description='最多处理1000条安全事件，超过1000条只处理前1000条，并'
                              '在响应的detail字段提示'
    ))
    def put(self, request):
        return super().put(request)


class ResolveAllSecurityView(ResolveAllAlertView):
    queryset = SecurityEvent.objects.all()
    filter_class = SecurityEventFilter
    model = SecurityEvent
    message = '每次处理上限为1000，本次已处理了1000条安全事件'

    @method_decorator(swagger_auto_schema(
        query_serializer=SecurityEventFilterSerializer(),
        operation_summary='批量处理筛选条件下的安全事件',
        operation_description='最多处理1000条安全事件，超过1000条只处理前1000条，并'
                              '在响应的detail字段提示'
    ))
    def put(self, request):
        return super().put(request)


class AuditorProtocolView(GenericAPIView):
    permission_classes = (IsConfiEngineer,)
    pagination_class = None
    serializer_class = AuditorProtocolSerializer

    default = {'count': 0, 'page_count': 0, 'results': []}

    @method_decorator(swagger_auto_schema(
        operation_summary='协议审计接口',
        query_serializer=AuditorProtocolQuerySerializer(),
    ))
    def get(self, request):
        query = AuditorProtocolQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        auditor = Device.objects.filter(type=Device.AUDITOR,
                                        register_status=Device.REGISTERED).first()
        if not auditor:
            return Response(self.default)
        sync = AuditorProtocolInterface(auditor)
        try:
            data = sync.request_for_data(**query.data)
        except Exception:
            raise CustomError(error_code=CustomError.AUDITOR_PROTOCOL_FAIL)
        return Response(data)
