from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet, ModelViewSet
from rest_framework_extensions.mixins import NestedViewSetMixin

from auditor import audit_requests
from auditor.models import AuditWhiteListStrategy, AuditBlackListStrategy
from auditor.serializers import AuditWhiteListStrategySerializer, \
    AuditBlackListStrategySerializer, ActivationSerialzier, \
    AuditBlackListStrategyDetailSerializer, \
    BatchAuditorSerialzier
from base_app.models import Device, StrategyTemplate
from base_app.serializers import DeviceRetrieveSerializer, \
    TemplateSerializer, RegisterSerializer, \
    UnRegisterSerializer, \
    AuditorFirewallDeviceSerializer
from base_app.tasks import auditor_sync_strategies
from base_app.views import DeviceView, TemplateView, check_or_update_device_strategy_apply_status
from utils.core.mixins import MultiActionConfViewSetMixin
from utils.core.permissions import IsConfiEngineer


class AuditDeviceView(DeviceView):

    queryset = Device.objects.filter(type=Device.AUDITOR, monitor=True,
                                     register_status=Device.REGISTERED)
    serializer_action_classes = {
        'list': AuditorFirewallDeviceSerializer,
        'retrieve': DeviceRetrieveSerializer,
        'register': RegisterSerializer,
        'un_register': UnRegisterSerializer,
        'to_temp': TemplateSerializer,
    }

    search_fields = ('name', 'ip', 'responsible_user', 'location')
    filter_fields = ('template_name', 'status', )
    permission_classes = (IsConfiEngineer,)

    def perform_batch_reboot(self, serializer):
        audit_requests.reboot(serializer)

    def perform_batch_un_register(self, serializer):
        audit_requests.un_register(serializer)

    def get_device_type(self):
        return Device.AUDITOR

    @action(methods=['put'], detail=True, permission_classes=[IsConfiEngineer])
    def sync_strategies(self, request, pk):
        """
        custom_swagger: 自定义 api 接口文档
        put:
          request:
            description:  put 方法同步单个审计的策略到综管平台
          response:
            200:
              description: '200'
        """
        auditor = self.get_object()
        auditor.apply_time = timezone.localtime()
        auditor.save()

        # todo 是不是需要改成异步策略

        auditor_sync_strategies(auditor)
        # sync_strategies_task.delay(pk)
        return Response(status=status.HTTP_200_OK)

    # @list_route(methods=['post'], permission_classes=[IsConfiEngineer])
    # def batch_apply_strategies(self, request):
    #     """
    #     custom_swagger: 自定义 api 接口文档
    #     post:
    #       request:
    #         description:  post 方法批量应用综管策略到多个审计
    #       response:
    #         201:
    #           description: '200'
    #     """
    #     # todo 批量策略管理下发功能，第一期不做后续会做
    #
    #     serializer = BatchAuditorSerialzier(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     ids = serializer.validated_data.get('ids')
    #     if ids:
    #         batch_apply_strategies_task.delay(ids)
    #
    #     return Response(status=status.HTTP_200_OK)

    # @list_route(methods=['post'], permission_classes=[IsConfiEngineer])
    # def batch_sync_strategies(self, request):
    #     """
    #     custom_swagger: 自定义 api 接口文档
    #     post:
    #       request:
    #         description:  post 方法批量同步多个审计的策略
    #       response:
    #         201:
    #           description: '200'
    #     """
    #     # todo 批量策略管理同步功能，第一期不做后续会做
    #     serializer = BatchAuditorSerialzier(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     ids = serializer.validated_data.get('ids')
    #     if ids:
    #         batch_sync_strategies_task.delay(ids)
    #         #
    #         # print('批量的 id', type(ids), ids, list(ids))
    #         # for id in ids:
    #         #     device = Device.objects.get(id=id)
    #         #     auditor_sync_strategies(device)
    #     # print('批量同步接口成功')
    #     return Response(status=status.HTTP_200_OK)


class AuditTemplateView(TemplateView):

    queryset = StrategyTemplate.objects.filter(type=Device.AUDITOR)
    permission_classes = (IsConfiEngineer,)

    def get_device_type(self):
        return Device.AUDITOR


class WhiteListStrategyView(NestedViewSetMixin, ModelViewSet):
    permission_classes = (IsConfiEngineer,)

    queryset = AuditWhiteListStrategy.objects.filter(device__type=Device.AUDITOR)
    serializer_class = AuditWhiteListStrategySerializer
    search_fields = ('id', 'name', 'src_ip', 'dst_ip')
    filter_fields = ('is_active', 'protocol', 'source')

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        select_ids = queryset.values_list('id', flat=True)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.paginator.get_paginated_response(serializer.data,
                                                         select_ids=select_ids)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(methods=['put'], detail=False, permission_classes=[IsConfiEngineer])
    def batch_activation(self, request, **kwargs):
        serializer = BatchAuditorSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_activation(serializer, **kwargs)
        return Response(serializer.data)

    def perform_batch_activation(self, serializer, **kwargs):
        raise NotImplementedError('`perform_bath_activation()` must be implemented.')


class BlackListStrategyView(NestedViewSetMixin,
                            MultiActionConfViewSetMixin,
                            ListModelMixin,
                            RetrieveModelMixin,
                            GenericViewSet):

    queryset = AuditBlackListStrategy.objects.filter(device__type=Device.AUDITOR)
    serializer_class = AuditBlackListStrategySerializer
    serializer_action_classes = {
        'list': AuditBlackListStrategySerializer,
        'retrieve': AuditBlackListStrategyDetailSerializer,
        'activation': ActivationSerialzier,
        'batch_activation': BatchAuditorSerialzier,
    }
    permission_classes = (IsConfiEngineer,)
    search_fields = ('id', 'name')
    filter_fields = ('is_active','source', 'level')

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        select_ids = queryset.values_list('id', flat=True)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.paginator.get_paginated_response(serializer.data, select_ids=select_ids)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    @action(methods=['put'], detail=True, permission_classes=[IsConfiEngineer])
    def activation(self, request, pk=None, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        strategy = self.get_object()
        strategy.is_active = serializer.validated_data['is_active']
        strategy.save(update_fields=['is_active'])
        return Response(serializer.data)

    @action(methods=['put'], detail=False, permission_classes=[IsConfiEngineer])
    def batch_activation(self, request, **kwargs):
        serializer = BatchAuditorSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_activation(serializer, **kwargs)
        return Response(serializer.data)

    def perform_batch_activation(self, serializer, **kwargs):
        raise NotImplementedError('`perform_bath_activation()` must be implemented.')


class TempWhiteListStrategyView(WhiteListStrategyView):

    queryset = AuditWhiteListStrategy.objects.filter(template__type=Device.AUDITOR)
    permission_classes = (IsConfiEngineer,)

    def perform_create(self, serializer):
        serializer.save(template_id=self.kwargs['parent_lookup_template'])

    def perform_batch_activation(self, serializer, **kwargs):
        ids = serializer.validated_data.get('ids')
        if ids:
            AuditWhiteListStrategy.objects.filter(template_id=kwargs['parent_lookup_template'], id__in=ids).update(
                is_active=serializer.validated_data['is_active'])
        else:
            AuditWhiteListStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
                is_active=serializer.validated_data['is_active'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取模板下的白名单的统计信息
          response:
            200:
              description: 白名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的白名单数量,
                              "count_enable": 0  /# 启用的白名单数量,
                          }
        """

        temp_id = self.kwargs['parent_lookup_template']
        queryset = self.queryset.filter(template_id=temp_id)
        count_all = queryset.count()
        count_enable = queryset.filter(is_active=True).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
        )
        return Response(data)


class TempBlackListStrategyView(BlackListStrategyView):

    queryset = AuditBlackListStrategy.objects.filter(template__type=Device.AUDITOR)

    def perform_batch_activation(self, serializer, **kwargs):
        ids = serializer.validated_data['ids']
        if ids:
            AuditBlackListStrategy.objects.filter(template_id=kwargs['parent_lookup_template'], id__in=ids).update(
                is_active=serializer.validated_data['is_active'])
        else:
            AuditBlackListStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
                is_active=serializer.validated_data['is_active'])

    def perform_create(self, serializer):
        serializer.save(template_id=self.kwargs['parent_lookup_template'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取模板下的黑名单的统计信息
          response:
            200:
              description: 黑名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的黑名单数量,
                              "count_enable": 0  /# 启用的黑名单数量,
                          }
        """
        temp_id = self.kwargs['parent_lookup_template']
        queryset = self.queryset.filter(template_id=temp_id)
        count_all = queryset.count()
        count_enable = queryset.filter(is_active=True).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
        )
        return Response(data)


class DeviceWhiteListStrategyView(WhiteListStrategyView):

    queryset = AuditWhiteListStrategy.objects.filter(device__type=Device.AUDITOR)
    search_fields = ('id', 'name',)
    filter_fields = ('is_active', 'protocol')

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    def perform_batch_activation(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        ids = serializer.validated_data.get('ids')
        if ids:
            AuditWhiteListStrategy.objects.filter(device_id=kwargs['parent_lookup_device'], id__in=ids).update(
                is_active=serializer.validated_data['is_active'])
        else:
            AuditWhiteListStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
                is_active=serializer.validated_data['is_active'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取审计设备下白名单的统计信息
          response:
            200:
              description: 白名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的白名单数量,
                              "count_enable": 0  /# 启用的白名单数量,
                              "apply_time": 2020-12-12  /# 策略更新时间 ,
                          }
        """

        device = Device.objects.get(id=self.kwargs['parent_lookup_device'])

        count_all = AuditWhiteListStrategy.objects.filter(device=device).count()
        count_enable = AuditWhiteListStrategy.objects.filter(device=device, is_active=True).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
            apply_time=timezone.localtime(device.apply_time)
        )
        return Response(data)


class DeviceBlackListStrategyView(BlackListStrategyView):

    search_fields = ('id', 'name', 'cve', 'cnnvd')
    filter_fields = ('is_active', 'source', 'level')

    queryset = AuditBlackListStrategy.objects.filter(device__type=Device.AUDITOR)

    def perform_batch_activation(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        ids = serializer.validated_data.get('ids')
        if ids:
            AuditBlackListStrategy.objects.filter(device_id=kwargs['parent_lookup_device'], id__in=ids).update(
                is_active=serializer.validated_data['is_active'])
        else:
            AuditBlackListStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
                is_active=serializer.validated_data['is_active'])

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取审计设备下黑名单的统计信息
          response:
            200:
              description: 黑名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的黑名单数量,
                              "count_enable": 0  /# 启用的黑名单数量,
                              "apply_time": 2020-12-12  /# 策略更新时间 ,
                          }
        """
        device = Device.objects.get(id=self.kwargs['parent_lookup_device'])
        count_all = AuditBlackListStrategy.objects.filter(device=device).count()
        count_enable = AuditBlackListStrategy.objects.filter(device=device, is_active=True).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
            apply_time=timezone.localtime(device.apply_time)
        )
        return Response(data)

