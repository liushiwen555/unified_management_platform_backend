from django.conf import settings
from django.db.models import Q
from django.db.models.signals import post_save
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.utils.encoding import escape_uri_path
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import CreateModelMixin, ListModelMixin, \
    RetrieveModelMixin, UpdateModelMixin, \
    DestroyModelMixin
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from base_app.device_import import get_devices
from base_app.filters import DeviceFilter, CategoryDeviceFilter
from base_app.models import BaseStrategy, SECRET_LEN
from base_app.serializers import *
from base_app.signals import template_post_save
from base_app.tasks import apply_strategies_task, deploy_to_device_task
from snmp.models import SNMPSetting, SNMPData
from snmp.serializers import SNMPSettingSerializer, SNMPDataSerializer
from utils.context import temporary_disconnect_signal
from utils.core.exceptions import CustomError
from utils.core.mixins import \
    ConfiEngineerPermissionsMixin as EngineerPermissionsMixin, \
    MultiMethodAPIViewMixin
from utils.core.permissions import IsConfiEngineer
from utils.core.renders import XLSXRenderer, ExportXLSXRenderer
from utils.core.serializers import get_schema_response
from utils.helper import random_string

DEFAULT_DEPLOY_TEMPLATE_NAME = '来自{}的策略'


def check_or_update_device_strategy_apply_status(device: Device):
    """
    更新设备的策略时，判断该设备是否正在下发策略，如果是，则报错。
    如果不是，则更新设备的状态为策略未下发
    :param device: 设备
    :return:
    """
    if device.strategy_apply_status == device.STRATEGY_APPLY_STATUS_APPLYING:
        raise CustomError({'error': CustomError.EDIT_STRATEGY_WHILE_APPLYING})
    else:
        device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_UN_APPLIED
        device.save(update_fields=['strategy_apply_status'])


class HeartbeatView(APIView):

    def get(self, request, *args, **kwargs):
        return Response()


class DeviceView(ListModelMixin,
                 RetrieveModelMixin,
                 UpdateModelMixin,
                 EngineerPermissionsMixin,
                 GenericViewSet):
    """
    设备管理的base view，继承该类的view需要以当前设备的dev_type
    覆盖queryset和perform_create
    例：
    queryset = Device.objects.filter(dev_type=1)
    def perform_create(self, serializer):
        serializer.save(dev_type=1)
    """
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer

    def retrieve(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取审计或防火墙资产详情信息，审计入口"/auditor/device"防火墙入口"/firewall/device"
          response:
            401:
              description: '401'
            403:
              description: '403'
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        device_detail = serializer.data

        # 只有配置工程师能够看到关联码
        if self.request.user.group.name != IsConfiEngineer.GROUP_NAME:
            device_detail.pop('register_code')
        return Response(device_detail)

    def list(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取审计或者防火墙资产列表，审计入口 "/auditor/device" 防火墙入口 "/firewall/device"
          response:
            401:
              description: '401'
            403:
              description: '403'
        """
        queryset = self.filter_queryset(self.get_queryset())
        page_param = self.request.query_params.get('page', None)
        if page_param is not None:
            page = self.paginate_queryset(queryset)
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    # @list_route(methods=['post'], permission_classes=[IsConfiEngineer])
    # def batch_operation(self, request):
    #     # （第一版不包含该功能）
    #     """
    #     custom_swagger: 自定义 api 接口文档
    #     post:
    #       request:
    #         description:  post 批量操作方法 批量重启或者批量解注册功能
    #       response:
    #         401:
    #           description: '401'
    #         403:
    #           description: '403'
    #     """
    #
    #     serializer = BatchOperationSerializer(data=request.data)
    #     serializer.is_valid(raise_exception=True)
    #     if not self.request.user.check_password(serializer.validated_data['password']):
    #         raise CustomError({'error': CustomError.ADMIN_PSW_ERROR})
    #     if serializer.data['operation'] == BatchOperationSerializer.REBOOT:
    #         self.perform_batch_reboot(serializer)
    #     elif serializer.data['operation'] == BatchOperationSerializer.UN_REGISTER:
    #         self.perform_batch_un_register(serializer)
    #         Device.objects.filter(id__in=serializer.data['dev_ids']).update(
    #             status=Device.NOT_REGISTERED, ip=None, version=None, registered_time=None)
    #     return Response()
    #
    # @list_route(methods=['post'], permission_classes=[IsConfiEngineer])
    # def clear_unregistered(self, request):
    # （第一版不包含该功能）
    #     """
    #     custom_swagger: 自定义 api 接口文档
    #     get:
    #       request:
    #         description:  get 方法清除所有审计或者防火墙未关联的设备
    #       response:
    #         200:
    #           description: '200'
    #     """
    #     Device.objects.filter(type=self.get_device_type(), status=Device.NOT_REGISTERED).delete()
    #     return Response()

    @action(methods=['post'], detail=False, permission_classes=[])
    def register(self, request):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description:  post 方法把审计或者防火墙关联到综管平台, 该接口前端不需要
          response:
            201:
              description: ' '
        """
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = get_object_or_404(Device,
                                   register_code=serializer.validated_data[
                                       'register_code'])
        # 审计取消关联后，综管状态不更新
        # if device.status != Device.NOT_REGISTERED:
        #     raise CustomError({'error': CustomError.DEVICE_ALREADY_REGISTERED})
        device.ip = serializer.validated_data['ip']
        device.version = serializer.validated_data['version']
        device.registered_time = timezone.localtime()
        device.register_status = Device.REGISTERED
        device.secret = random_string(SECRET_LEN)
        device.save()
        if device.type == Device.AUDITOR:
            return Response({'secret': device.secret})
        else:
            return Response()

    @action(methods=['post'], detail=False, permission_classes=[])
    def un_register(self, request):
        # （第一版不包含该功能）
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description:  post 方法把审计或者防火墙从综管平台解绑
          response:
            201:
              description: ' '
        """

        try:
            device = Device.objects.get(ip=request.META['REMOTE_ADDR'])
            device.register_status = Device.NOT_REGISTERED
            device.version = None
            device.registered_time = None
            device.save(
                update_fields=['register_status', 'version', 'registered_time'])
            return Response()
        except Device.DoesNotExist as e:
            raise CustomError({'error': CustomError.IP_NOT_MATCH})

    @action(methods=['post'], detail=True, permission_classes=[IsConfiEngineer])
    def to_temp(self, request, pk):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description:  post 方法，保存某一个审计或者防火墙设备的策略到模板
          response:
            201:
              description: ' '
        """
        serializer = TemplateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with temporary_disconnect_signal(post_save, template_post_save,
                                         StrategyTemplate):
            instance = serializer.save(type=self.get_device_type())
        BaseStrategy.dev_to_temp(pk, instance.id, self.get_device_type())
        return Response(status=status.HTTP_200_OK)

    @action(methods=['post'], detail=True, permission_classes=[IsConfiEngineer])
    def apply_strategies(self, request, pk):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description:  post 方法，将综管上策略下发到某一审计或防火墙设备
            body_api_from_doc: true
          response:
            201:
              description: '状态码实际是200，（文档bug, 只能暂时在这里备注一下了） '
            499:
              description: '{"error": "1018"}'
            499':
              description: '{"error": "1011"}'
        """
        device = self.get_object()

        # 取消在线才能下发功能
        # if device.status != Device.ONLINE:
        #     raise CustomError({'error': CustomError.APPLY_STRATEGY_FAIL_DEVICE_OFFLINE})

        device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLYING
        device.apply_time = timezone.localtime()
        device.save(update_fields=['strategy_apply_status', 'apply_time'])
        apply_strategies_task.delay(pk)
        return Response(status=status.HTTP_200_OK)

    def perform_create(self, serializer):
        type = self.get_device_type()
        category = Device.CATEGORY_CHOICE.get('CATEGORY_Other', 0)
        if type in ['1', '2', '3', '4', '5', '6']:
            category = Device.CATEGORY_CHOICE.get('CATEGORY_Security', 0)

        serializer.save(type=type, category=category)

    def perform_batch_reboot(self, serializer):
        raise NotImplementedError(
            '`perform_batch_reboot()` must be implemented.')

    def perform_batch_un_register(self, serializer):
        raise NotImplementedError(
            '`perform_batch_un_register()` must be implemented.')

    def get_device_type(self):
        raise NotImplementedError('`get_device_type()` must be implemented.')


class DeviceBaseView(CreateModelMixin,
                     ListModelMixin,
                     RetrieveModelMixin,
                     UpdateModelMixin,
                     DestroyModelMixin,
                     EngineerPermissionsMixin,
                     GenericViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer

    serializer_action_classes = {
        'list': DeviceListSerializer,
        'retrieve': DeviceRetrieveSerializer,
        'create': DeviceSerializer,
        'update': DeviceUpdateSerializer,
        'batch_operation': BatchOperationSerializer,
        "category_device_list": DeviceCategorySerializer,
        "category_device_detail": DeviceRetrieveSerializer,
        'snmp_setting': SNMPSettingSerializer,
        'snmp_data': SNMPDataSerializer,
        'log_setting': LogSettingSerializer,
        'import_device_file': ImportDeviceSerializer,
    }

    ordering_fields = (
        'id', 'type', 'value', 'cpu_in_use', 'memory_in_use', 'disk_in_use',
        'network_in_speed', 'network_out_speed')
    filter_class = DeviceFilter
    permission_classes = (IsConfiEngineer,)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @method_decorator(swagger_auto_schema(
        responses={'499': get_schema_response('IP或MAC地址重复')}
    ))
    def create(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description:  post 方法新增资产
        """
        data_from_user = request.data
        # if not data_from_user.get('mac'):
        #     data_from_user.pop('mac')
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = serializer.save()
        serialized_data = serializer.data
        headers = self.get_success_headers(serialized_data)

        serialized_data['id'] = device.id  # 用于日志记录ID
        return Response(serialized_data, status=status.HTTP_201_CREATED,
                        headers=headers)

    @method_decorator(swagger_auto_schema(
        responses={'499': get_schema_response('IP或MAC地址重复')}
    ))
    def update(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        put:
          request:
            description:  put 方法修改设备信息
        """
        return super(DeviceBaseView, self).update(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        # 返回资产详情内容，所有部分
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        device_detail = serializer.data

        # # 只有配置工程师能够看到关联码
        if self.request.user.group.name != IsConfiEngineer.GROUP_NAME:
            device_detail.pop('register_code')
        return Response(device_detail)

    @method_decorator(swagger_auto_schema(
        query_serializer=DeviceFilterSerializer(),
    ))
    def list(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description:  get 方法获取所有资产的列表，query 带参数可以选择不同种类的设备以及设置搜索条件
          response:
            401:
              description: '401'
            403:
              description: '403'
        """
        queryset = self.filter_queryset(self.get_queryset())
        category = self.request.query_params.get('category')
        type = self.request.query_params.get('type')

        if category == '1':
            queryset = queryset.filter(category=1,
                                       type__in=[0, 1, 2, 3, 4, 5, 6])
        if category == '2':
            queryset = queryset.filter(category=2, type__in=[0, 7, 8])
        if category == '3':
            queryset = queryset.filter(category=3, type__in=[0, 9, 10, 11])
        if category == '4':
            queryset = queryset.filter(category=4, type__in=[0, 12])

        if type in ['1', '2', '3', '4', '5', '6']:
            queryset = queryset.filter(category=1)

        if type in ['7', '8']:
            queryset = queryset.filter(category=2)

        if type in ['9', '10', '11']:
            queryset = queryset.filter(category=3)

        if type in ['12']:
            queryset = queryset.filter(category=4)
        self.queryset = queryset
        return super().list(request, *args, **kwargs)

    @action(methods=['get', 'put'], detail=True)
    def snmp_setting(self, request, pk):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取资产的SNMP设置
        put:
          request:
            description: 更新资产的SNMP设置
        """
        if request.method == 'GET':
            return self.get_snmp_setting(pk)
        else:
            return self.put_snmp_setting(request, pk)

    @action(methods=['get'], detail=True)
    def snmp_data(self, request, pk):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取资产的性能数据
        """
        instance = SNMPData.objects.filter(device=pk).first()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def get_snmp_setting(self, pk):
        instance, _ = SNMPSetting.objects.get_or_create(device_id=pk)
        serializer = self.get_serializer(instance)

        return Response(serializer.data)

    def put_snmp_setting(self, request, pk):
        instance = SNMPSetting.objects.get(device_id=pk)
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)

    @action(methods=['get', 'put'], detail=True)
    def log_setting(self, request, pk):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取资产的日志设置
        put:
          request:
            description: 更新资产的日志设置
        """
        if request.method == 'GET':
            return self.get_log_setting(pk)
        else:
            return self.put_log_setting(request, pk)

    def get_log_setting(self, pk):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        return Response(serializer.data)

    def put_log_setting(self, request, pk):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data,
                                         partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)

    @method_decorator(swagger_auto_schema(
        operation_summary='从导入文件里解析成功的资产批量导入',
        operation_description='返回从excel文件里解析得到的资产列表，需要区分开用'
                              'valid区分开是否解析成功',
        request_body=ImportDeviceBody(),
        responses={'200': openapi.Response('资产导入的解析结果',
                                           ImportDeviceSerializer()),
                   '499': '批量导入失败'},
    ))
    @action(methods=['post'], detail=False, permission_classes=[IsConfiEngineer])
    def import_device_file(self, request):
        myfile = request.FILES.getlist('file')
        if myfile:
            up_file = myfile[0]
            data = get_devices(up_file)
            serializer = self.get_serializer(data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            raise CustomError(
                {'error': CustomError.BULK_IMPORT_DEVICE_TEMP_ERROR})


class DeviceMonitorTresholdView(GenericAPIView):
    permission_classes = (IsConfiEngineer,)
    serializer_class = DeviceMonitorTresholdSerializer

    @method_decorator(swagger_auto_schema(deprecated=True))
    def get(self, request, *args, **kwargs):
        """
       custom_swagger: 自定义 api 接口文档
       get:
         request:
           description:  所有资产监控的使用阈值设置信息
         response:
            200:
              description: 所有资产监控的使用阈值设置信息
              response:
                examples1:
                      {
                        'security_cpu_alert_percent':10,
                        'security_memory_alert_percent':10,
                        'security_disk_alert_percent':10,
                        'communication_cpu_alert_percent':10,
                        'communication_memory_alert_percent':10,
                        'communication_disk_alert_percent':10,
                        'server_cpu_alert_percent':10,
                        'server_memory_alert_percent':10,
                        'server_disk_alert_percent':10,
                        'control_cpu_alert_percent':10,
                        'control_memory_alert_percent':10,
                      }
       """

        setting_rec, created = DeviceMonitorSetting.objects.get_or_create(id=1)
        serializer = DeviceMonitorTresholdSerializer(setting_rec)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @method_decorator(swagger_auto_schema(deprecated=True))
    def patch(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        patch:
          request:
            description:  patch 修改使用阈值设置信息
        """
        setting_rec, created = DeviceMonitorSetting.objects.get_or_create(id=1)
        serializer = DeviceMonitorTresholdSerializer(setting_rec,
                                                     data=request.data,
                                                     partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)


class DeviceMonitorFrequencyView(GenericAPIView):
    permission_classes = (IsConfiEngineer,)
    serializer_class = DeviceMonitorFrequencySerializer

    @method_decorator(swagger_auto_schema(deprecated=True))
    def get(self, request, *args, **kwargs):
        """
       custom_swagger: 自定义 api 接口文档
       get:
         request:
           description:  get 方法获取资产监控的频率设置信息
         response:
            200:
              description: 资产监控的频率设置信息
              response:
                examples1:
                      {
                        'security_monitor_period':10,
                        'communication_monitor_period':10,
                        'server_monitor_period':10,
                        'control_monitor_period':10,
                      }
       """

        setting_rec, created = DeviceMonitorSetting.objects.get_or_create(id=1)
        serializer = DeviceMonitorFrequencySerializer(setting_rec)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @method_decorator(swagger_auto_schema(deprecated=True))
    def patch(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        patch:
          request:
            description:  修改 资产监控的频率设置信息
        """
        setting_rec, created = DeviceMonitorSetting.objects.get_or_create(id=1)
        serializer = DeviceMonitorFrequencySerializer(setting_rec,
                                                      data=request.data,
                                                      partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)


class TemplateView(EngineerPermissionsMixin, ModelViewSet):
    pagination_class = None
    queryset = StrategyTemplate.objects.all()
    serializer_class = TemplateSerializer
    serializer_action_classes = {
        'list': TemplateSerializer,
        'retrieve': TemplateSerializer,
        'create': TemplateSerializer,
        'update': TemplateUpdateSerializer,
        'destroy': TemplateSerializer,
        'to_new_temp': TemplateSerializer,
        'deploy_to_device': DeployTemp2DeviceSerializer,
    }
    search_fields = ('name',)
    permission_classes = (IsConfiEngineer,)

    MAX_TEMPLATE_NUM = 20

    def create(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description: 新建模板
          response:
            400:
              description: 模板数量过多，不能新建
              response:
                examples1:
                          {
                              "error": 模板数量超过最大的允许值，
                          }
        """
        q = self.queryset
        if q.count() >= self.MAX_TEMPLATE_NUM:
            d = dict(
                error=f"允许最大的模板数量超过 {self.MAX_TEMPLATE_NUM} 个"
            )
            return Response(status=status.HTTP_400_BAD_REQUEST, data=d)
        else:
            return super(TemplateView, self).create(request, *args, **kwargs)

    @action(methods=['post'], detail=True, permission_classes=[IsConfiEngineer])
    def to_new_temp(self, request, pk):
        serializer = TemplateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with temporary_disconnect_signal(post_save, template_post_save,
                                         StrategyTemplate):
            instance = serializer.save(type=self.get_device_type())
        BaseStrategy.temp_to_temp(pk, instance.id, self.get_device_type())
        return Response(status=status.HTTP_200_OK)

    @action(methods=['post'], detail=True, permission_classes=[IsConfiEngineer])
    def deploy_to_device(self, request, pk):
        """
        先将策略模板更新到本地的设备，并把设备置为策略下发中状态
        然后异步下发策略
        :param request:
        :param pk: 策略模板id
        :return:
        """
        serializer = DeployTemp2DeviceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        dev_ids = serializer.validated_data['dev_ids']
        for device_id in dev_ids:
            BaseStrategy.del_dev_strategies(device_id, self.get_device_type())
            BaseStrategy.temp_to_dev(device_id, pk, self.get_device_type())
        # Device.objects.filter(
        #         id__in=dev_ids,
        #         type=self.get_device_type(),
        #         status=Device.ONLINE,
        #         register_status=Device.REGISTERED
        #     ).update(strategy_apply_status=Device.STRATEGY_APPLY_STATUS_APPLYING)

        Device.objects.filter(id__in=dev_ids,
                              type=self.get_device_type()).update(
            strategy_apply_status=Device.STRATEGY_APPLY_STATUS_APPLYING)
        deploy_to_device_task.delay(pk, dev_ids, self.get_device_type())
        return Response(status=status.HTTP_200_OK)

    def perform_create(self, serializer):
        serializer.save(type=self.get_device_type())

    def get_device_type(self):
        raise NotImplementedError('`get_device_type()` must be implemented.')


class ExportDeviceView(EngineerPermissionsMixin, GenericAPIView):
    """
    批量下载指定的资产
    """
    queryset = Device.objects.all()
    serializer_class = DeviceExportSerializer
    renderer_classes = (ExportXLSXRenderer, JSONRenderer)
    pagination_class = None

    @method_decorator(swagger_auto_schema(
        query_serializer=DeviceExportSerializer(),
        responses={'200': '下载的文件'},
        operation_summary='导出指定id列表的资产'
    ))
    def get(self, request):
        serializer = self.get_serializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        dev_ids = serializer.data['id']
        devices = self.get_queryset().filter(id__in=dev_ids)
        device_data = DeviceExportDataSerializer(devices, many=True).data

        response = Response(data=device_data)
        filename = '导出资产{time}.{format}'.format(
            time=timezone.now().strftime('%Y%m%d %H%M%S'),
            format='xlsx'
        )
        response['Content-Disposition'] = "attachment; filename*=utf-8''{filename}".format(
            filename=escape_uri_path(filename))
        return response


class ExportAllDeviceView(EngineerPermissionsMixin, GenericAPIView):
    """
    批量下载给定筛选条件的资产
    """
    queryset = Device.objects.all()
    serializer_class = DeviceFilterSerializer
    renderer_classes = (ExportXLSXRenderer, JSONRenderer)
    filter_class = DeviceFilter
    pagination_class = None

    @method_decorator(swagger_auto_schema(
        query_serializer=DeviceFilterSerializer(),
        responses={'200': '下载的文件'},
        operation_summary='导出给定筛选条件的资产'
    ))
    def get(self, request):
        serializer = self.get_serializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        devices = self.filter_class(serializer.data, queryset=self.get_queryset()).qs
        device_data = DeviceExportDataSerializer(devices, many=True).data

        response = Response(data=device_data)
        filename = '导出资产{time}.{format}'.format(
            time=timezone.now().strftime('%Y%m%d %H%M%S'),
            format='xlsx'
        )
        response['Content-Disposition'] = "attachment; filename*=utf-8''{filename}".format(
            filename=escape_uri_path(filename))
        return response


class ExportDeviceTemplateView(APIView):
    renderer_classes = (XLSXRenderer, )
    permission_classes = (IsConfiEngineer, )

    @method_decorator(swagger_auto_schema(
        operation_summary='批量导入资产模板模板下载'
    ))
    def get(self, request):
        file_name = '批量导入资产模板.xlsx'
        unified_forum_path = settings.MEDIA_ROOT
        file_path = unified_forum_path + file_name

        with open(file_path, 'rb') as f:
            response = Response(data=f.read())
        response['Content-Disposition'] = "attachment; filename*=utf-8''{filename}".format(
            filename=escape_uri_path(file_name))
        return response


class CategoryDeviceList(GenericAPIView):
    """
    分类监控资产的列表获取
    """
    serializer_class = DeviceCategorySerializer
    queryset = Device.objects.filter(Q(monitor=True) | Q(log_status=True))
    permission_classes = (IsConfiEngineer, )
    filter_class = CategoryDeviceFilter

    def get(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        category = self.request.query_params.get('category')
        type = self.request.query_params.get('type')

        if category == '1':
            queryset = queryset.filter(category=1,
                                       type__in=[0, 1, 2, 3, 4, 5, 6])
        if category == '2':
            queryset = queryset.filter(category=2, type__in=[0, 7, 8])
        if category == '3':
            queryset = queryset.filter(category=3, type__in=[0, 9, 10, 11])
        if category == '4':
            queryset = queryset.filter(category=4, type__in=[0, 12])

        if type in ['1', '2', '3', '4', '5', '6']:
            queryset = queryset.filter(category=1)

        if type in ['7', '8']:
            queryset = queryset.filter(category=2)

        if type in ['9', '10', '11']:
            queryset = queryset.filter(category=3)

        if type in ['12']:
            queryset = queryset.filter(category=4)

        if type in ['0']:
            queryset = queryset.filter(category__in=[1, 2, 3, 4])
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class DeviceAPIView(MultiMethodAPIViewMixin, GenericAPIView):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    filter_class = DeviceFilter
    permission_classes = (IsConfiEngineer, )

    serializer_method_classes = {
        'PUT': DeviceAllUpdateSerializer,
    }

    @method_decorator((swagger_auto_schema(
        query_serializer=DeviceFilterSerializer(),
        operation_description='批量更新所有资产，过滤条件放在query，修改内容放在body',
        operation_summary='根据筛选条件批量更新所有资产'
    )))
    def put(self, request, *args, **kwargs):
        serializer = DeviceAllUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        resp_data = serializer.data.copy()
        data_to_update = serializer.data

        queryset = self.filter_queryset(self.queryset)

        # 此内容是为了在响应里增加内容用于操作日志的记录
        device = queryset.first()
        count = queryset.count()
        resp_data['device'] = device.name if device else ''
        resp_data['id'] = device.id if device else ''
        resp_data['count'] = count

        dev_without_mac = queryset.filter(mac__isnull=True)
        dev_with_mac = queryset.filter(mac__isnull=False)
        dev_with_mac.update(**data_to_update)
        # 没有mac地址的资产无法做ipmac绑定
        data_to_update['ip_mac_bond'] = False
        dev_without_mac.update(**data_to_update)

        return Response(data=resp_data, status=status.HTTP_200_OK)


class DeviceBatchView(MultiMethodAPIViewMixin, GenericAPIView):
    """
    对资产进行批量操作的接口
    """
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer
    permission_classes = (IsConfiEngineer, )

    serializer_method_classes = {
        'DELETE': DeviceExportSerializer,
        'PUT': DeviceBulkUpdateSerializer,
        'POST': ImportDeviceSerializer,
    }

    @method_decorator(swagger_auto_schema(
        query_serializer=DeviceExportSerializer(),
        operation_summary='传递id列表批量删除资产',
        responses={'204': 'No Content'}
    ))
    def delete(self, request):
        serializer = self.get_serializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)
        dev_ids = serializer.data['id']
        Device.objects.filter(id__in=dev_ids).delete()

        return Response(status=status.HTTP_204_NO_CONTENT)

    @method_decorator(swagger_auto_schema(
        request_body=DeviceBulkUpdateSerializer(),
        operation_summary='传递id列表批量修改资产',
    ))
    def put(self, request):
        serializer = DeviceBulkUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        dev_ids = serializer.validated_data['ids']
        devs = Device.objects.filter(id__in=dev_ids)
        data_to_update = serializer.data

        if devs.count() == len(dev_ids):
            data_to_update.pop('ids')
            dev_without_mac = devs.filter(mac__isnull=True)
            dev_with_mac = devs.filter(mac__isnull=False)
            dev_with_mac.update(**data_to_update)

            data_to_update['ip_mac_bond'] = False
            dev_without_mac.update(**data_to_update)
            return Response(status=status.HTTP_200_OK)
        else:
            dev_not_exists = []
            for dev_id in dev_ids:
                dev_count = Device.objects.filter(id=dev_id).count()
                if dev_count == 0:
                    dev_not_exists.append(dev_id)

            d = dict(
                dev_not_exists=dev_not_exists
            )

            data_to_update.pop('ids')
            devs.update(**data_to_update)
            return Response(data=d, status=status.HTTP_200_OK)

    @method_decorator(swagger_auto_schema(
        request_body=ACKImportDeviceSerializer(),
        operation_summary='批量添加资产',
        operation_description='数据来源是通过批量导入资产获取的资产列表,'
                              '从列表里筛选出valid为True的存储',
        responses={'201': openapi.Response('批量导入资产结果',
                                           ImportDeviceSerializer(many=True))}
    ))
    def post(self, request):
        data = [r for r in request.data['data'] if r['valid']]
        serializer = self.get_serializer(data=data, many=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)
