import json

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import mixins
from rest_framework.decorators import action
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet, ModelViewSet
from rest_framework_extensions.mixins import NestedViewSetMixin

from base_app.models import Device, StrategyTemplate
from base_app.serializers import DeviceRetrieveSerializer, \
    TemplateSerializer, RegisterSerializer, \
    AuditorFirewallDeviceSerializer
from base_app.views import DeviceView, TemplateView, check_or_update_device_strategy_apply_status
from firewall import firewall_requests
from firewall.filters import FirewallSysEventFilter, FirewallSecEventFilter
from firewall.models import FirewallWhiteListStrategy, FirewallBlackListStrategy, FirewallIPMACBondStrategy, \
    BaseFirewallStrategy, ConfStrategy, IndustryProtocolDefaultConfStrategy, IndustryProtocolOPCStrategy, \
    IndustryProtocolModbusStrategy, IndustryProtocolS7Strategy, FirewallSecEvent, FirewallSysEvent, \
    FirewallLearnedWhiteListStrategy, FirewallIPMACUnknownDeviceActionStrategy
from firewall.serializers import FirewallWhiteListStrategySerializer, ActivationSerialzier, \
    FirewallBlackListStrategySerializer, FirewallBlackListStrategyDetailSerializer, \
    FirewallIPMACBondStrategySerializer, BaseFirewallStrategySerializer, ConfStrategySerializer, \
    IndustryProtocolDefaultConfStrategySerializer, IndustryProtocolOPCStrategySerializer, \
    IndustryProtocolModbusStrategySerializer, IndustryProtocolS7StrategySerializer, FirewallSecEventSerializer, \
    FirewallSysEventSerializer, ActionSerialzier, FirewallLearnedWhiteListStrategySerializer, \
    FirewallWhiteListStrategyLearnSerializer, FirewallLearnedWhiteListUploadSerializer, FirewallLogUploadSerializer, \
    FirewallIPMACUnknownDeviceActionStrategySerializer, \
    FirewallIPMACBondStrategyUploadSerializer, FirewallIPMACBondStrategyDetailSerializer
from log.views import BaseLogView
from utils.core.mixins import ConfiEngineerPermissionsMixin as EngineerPermissionsMixin
from utils.core.mixins import MultiActionConfViewSetMixin
from utils.core.permissions import IsConfiEngineer


class FirewallDeviceView(DeviceView):
    queryset = Device.objects.filter(type=Device.FIRE_WALL, monitor=True, status__in=[Device.ONLINE, Device.OFFLINE])

    serializer_action_classes = {
        'list': AuditorFirewallDeviceSerializer,
        'retrieve': DeviceRetrieveSerializer,
        'register': RegisterSerializer,
        # 'create': DeviceSerializer,
        # 'update': DeviceUpdateSerializer,
        'to_temp': TemplateSerializer,
        'strategy_conf': ConfStrategySerializer,
        'industry_protocol_default_conf_strategy': IndustryProtocolDefaultConfStrategySerializer,
        'industry_protocol_opc_strategy': IndustryProtocolOPCStrategySerializer,
    }

    search_fields = ('name', 'ip', 'responsible_user', 'location')
    filter_fields = ('template_name', 'status')
    permission_classes = (IsConfiEngineer,)

    def perform_batch_reboot(self, serializer):
        firewall_requests.reboot(serializer)

    def perform_batch_un_register(self, serializer):
        firewall_requests.un_register(serializer)

    def get_device_type(self):
        return Device.FIRE_WALL

    @action(methods=['get', 'put'], detail=True, url_path='strategy-conf', permission_classes=[IsConfiEngineer])
    def strategy_conf(self, request, pk=None):
        conf_strategy = get_object_or_404(ConfStrategy, device_id=pk)
        if request.method == 'GET':
            serializer = ConfStrategySerializer(conf_strategy)
            return Response(serializer.data)
        elif request.method == 'PUT':
            serializer = ConfStrategySerializer(conf_strategy, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

    @action(methods=['get', 'put'], detail=True, url_path='industry_protocol_default_conf_strategy',
                  permission_classes=[IsConfiEngineer])
    def industry_protocol_default_conf_strategy(self, request, pk=None):
        industry_protocol_default_conf_strategy = get_object_or_404(IndustryProtocolDefaultConfStrategy, device_id=pk)
        if request.method == 'GET':
            serializer = IndustryProtocolDefaultConfStrategySerializer(industry_protocol_default_conf_strategy)
            return Response(serializer.data)
        elif request.method == 'PUT':
            serializer = IndustryProtocolDefaultConfStrategySerializer(industry_protocol_default_conf_strategy,
                                                                       data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

    @action(methods=['get', 'put'], detail=True, url_path='industry_protocol_opc_strategy',
                  permission_classes=[IsConfiEngineer])
    def industry_protocol_opc_strategy(self, request, pk=None):
        industry_protocol_opc_strategy = get_object_or_404(IndustryProtocolOPCStrategy, device_id=pk)
        if request.method == 'GET':
            serializer = IndustryProtocolOPCStrategySerializer(industry_protocol_opc_strategy)
            return Response(serializer.data)
        elif request.method == 'PUT':
            serializer = IndustryProtocolOPCStrategySerializer(industry_protocol_opc_strategy, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)


class FirewallTemplateView(TemplateView):
    queryset = StrategyTemplate.objects.filter(type=Device.FIRE_WALL)
    permission_classes = (IsConfiEngineer,)

    def get_device_type(self):
        return Device.FIRE_WALL

    @action(methods=['get', 'put'], detail=True, url_path='strategy-conf', permission_classes=[IsConfiEngineer])
    def strategy_conf(self, request, pk=None):
        conf_strategy = get_object_or_404(ConfStrategy, template_id=pk)
        if request.method == 'GET':
            serializer = ConfStrategySerializer(conf_strategy)
            return Response(serializer.data)
        elif request.method == 'PUT':
            serializer = ConfStrategySerializer(conf_strategy, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

    @action(methods=['get', 'put'], detail=True, url_path='industry_protocol_default_conf_strategy',
                  permission_classes=[IsConfiEngineer])
    def industry_protocol_default_conf_strategy(self, request, pk=None):
        industry_protocol_default_conf_strategy = get_object_or_404(IndustryProtocolDefaultConfStrategy, template_id=pk)
        if request.method == 'GET':
            serializer = IndustryProtocolDefaultConfStrategySerializer(industry_protocol_default_conf_strategy)
            return Response(serializer.data)
        elif request.method == 'PUT':
            serializer = IndustryProtocolDefaultConfStrategySerializer(industry_protocol_default_conf_strategy,
                                                                       data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

    @action(methods=['get', 'put'], detail=True, url_path='industry_protocol_opc_strategy',
                  permission_classes=[IsConfiEngineer])
    def industry_protocol_opc_strategy(self, request, pk=None):
        industry_protocol_opc_strategy = get_object_or_404(IndustryProtocolOPCStrategy, template_id=pk)
        if request.method == 'GET':
            serializer = IndustryProtocolOPCStrategySerializer(industry_protocol_opc_strategy)
            return Response(serializer.data)
        elif request.method == 'PUT':
            serializer = IndustryProtocolOPCStrategySerializer(industry_protocol_opc_strategy, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)


class BaseFirewallStrategyView(NestedViewSetMixin, EngineerPermissionsMixin, ModelViewSet):
    queryset = BaseFirewallStrategy.objects.filter(device__type=Device.FIRE_WALL)
    serializer_class = BaseFirewallStrategySerializer
    filter_fields = ('protocol', 'action', 'logging', 'status')
    search_fields = ('id', 'rule_id', 'rule_name')
    permission_classes = (IsConfiEngineer,)

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_activation(self, request, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_activation(serializer, **kwargs)
        return Response(serializer.data)

    def perform_batch_activation(self, serializer, **kwargs):
        raise NotImplementedError('`perform_batch_activation()` must be implemented.')


class WhiteListStrategyView(NestedViewSetMixin, ModelViewSet):
    queryset = FirewallWhiteListStrategy.objects.filter(device__type=Device.FIRE_WALL)
    serializer_class = FirewallWhiteListStrategySerializer
    search_fields = ('id', 'rule_id', 'rule_name')
    filter_fields = ('status','protocol', 'logging')
    permission_classes = (IsConfiEngineer,)

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_activation(self, request, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_activation(serializer, **kwargs)
        return Response(serializer.data)

    def perform_batch_activation(self, serializer, **kwargs):
        raise NotImplementedError('`perform_batch_activation()` must be implemented.')


class LearnedWhiteListStrategyView(NestedViewSetMixin,
                                   mixins.RetrieveModelMixin,
                                   mixins.DestroyModelMixin,
                                   mixins.ListModelMixin,
                                   EngineerPermissionsMixin,
                                   GenericViewSet):
    queryset = FirewallLearnedWhiteListStrategy.objects.filter(device__type=Device.FIRE_WALL)
    serializer_class = FirewallLearnedWhiteListStrategySerializer
    search_fields = ('id', 'sid', 'rule_name')
    filter_fields = ('status',)
    permission_classes = (IsConfiEngineer,)

    @action(methods=['put'], detail=True, permission_classes=(IsConfiEngineer,))
    def activation(self, request, pk=None, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        strategy = self.get_object()
        strategy.status = serializer.validated_data['status']
        strategy.save()
        return Response()

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_activation(self, request, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        FirewallLearnedWhiteListStrategy.objects.all().update(status=serializer.data['status'])
        return Response(serializer.data)

    @action(methods=['put'], detail=True, permission_classes=(IsConfiEngineer,))
    def firewall_action(self, request, pk=None, **kwargs):
        serializer = ActionSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        strategy = self.get_object()
        strategy.action = serializer.validated_data['action']
        strategy.save()
        return Response()

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_firewall_action(self, request, **kwargs):
        serializer = ActionSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        FirewallLearnedWhiteListStrategy.objects.all().update(action=serializer.validated_data['action'])
        return Response()

    @action(methods=['post'], detail=False, permission_classes=(IsConfiEngineer,))
    def learn(self, request, **kwargs):
        serializer = FirewallWhiteListStrategyLearnSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device_id = kwargs['parent_lookup_device']
        firewall_requests.whitelist_learn(device_id, serializer)
        FirewallLearnedWhiteListStrategy.objects.filter(device_id=device_id).delete()
        FirewallIPMACBondStrategy.objects.filter(device_id=device_id).delete()
        return Response()

    @action(methods=['post'], detail=False, permission_classes=(IsConfiEngineer,))
    def stop_learn(self, request, **kwargs):
        device_id = kwargs['parent_lookup_device']
        firewall_requests.whitelist_stop_learn(device_id)
        return Response()

    @action(methods=['post'], detail=False, permission_classes=(IsConfiEngineer,))
    def give_up_learned_items(self, request, **kwargs):
        device_id = kwargs['parent_lookup_device']
        firewall_requests.del_all_learned_whitelist(device_id)
        FirewallLearnedWhiteListStrategy.objects.filter(device_id=device_id).delete()
        return Response()


class LearnedWhiteListUploadView(APIView):
    # permission_classes = (IsConfiEngineer,)
    permission_classes = ()
    def post(self, request, *args, **kwargs):
        ip = request.META['REMOTE_ADDR']
        firewall = get_object_or_404(Device, ip=ip)
        serializers = FirewallLearnedWhiteListUploadSerializer(data=json.loads(request.data['rules']), many=True)
        serializers.is_valid(raise_exception=True)
        serializers.save(device_id=firewall.id)
        return Response()


class IPMACUploadView(APIView):
    # permission_classes = (IsConfiEngineer,)
    permission_classes = ()
    def post(self, request, *args, **kwargs):
        ip = request.META['REMOTE_ADDR']
        firewall = get_object_or_404(Device, ip=ip)
        serializers = FirewallIPMACBondStrategyUploadSerializer(data=json.loads(request.data['rules']), many=True)
        serializers.is_valid(raise_exception=True)
        serializers.save(device_id=firewall.id)
        return Response()


# class IPMACUploadView(APIView):
#
#     def post(self, request, *args, **kwargs):
#         ip = request.META['REMOTE_ADDR']
#         firewall = get_object_or_404(Device, ip=ip)
#         ip_list = FirewallIPMACBondStrategy.objects.filter(device_id=firewall.id).values_list('ip', flat=True)
#         mac_list = FirewallIPMACBondStrategy.objects.filter(device_id=firewall.id).values_list('mac', flat=True)
#         data = json.loads(request.data['rules'])
#         valid_data = [x for x in data if x['ip'] not in ip_list and x['mac'] not in mac_list]
#         serializers = FirewallIPMACBondStrategyUploadSerializer(data=valid_data, many=True)
#         serializers.is_valid(raise_exception=True)
#         serializers.save(device_id=firewall.id)
#         return Response()


class BlackListStrategyView(NestedViewSetMixin,
                            MultiActionConfViewSetMixin,
                            ListModelMixin,
                            RetrieveModelMixin,
                            GenericViewSet):
    queryset = FirewallBlackListStrategy.objects.filter(device__type=Device.FIRE_WALL)
    serializer_class = FirewallBlackListStrategySerializer
    serializer_action_classes = {
        'list': FirewallBlackListStrategySerializer,
        'retrieve': FirewallBlackListStrategyDetailSerializer
    }
    permission_classes = (IsConfiEngineer,)
    search_fields = ('id', 'name')
    filter_fields = ('status','action', 'level')

    @action(methods=['put'], detail=True, permission_classes=(IsConfiEngineer,))
    def activation(self, request, pk=None, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        strategy = self.get_object()
        strategy.status = serializer.validated_data['status']
        strategy.save(update_fields=['status'])
        return Response(serializer.data)

    @action(methods=['put'], detail=True, permission_classes=(IsConfiEngineer,))
    def firewall_action(self, request, pk=None, **kwargs):
        serializer = ActionSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        strategy = self.get_object()
        strategy.action = serializer.validated_data['action']
        strategy.save(update_fields=['action'])
        return Response(serializer.data)

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_activation(self, request, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_activation(serializer, **kwargs)
        return Response(serializer.data)

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_firewall_action(self, request, **kwargs):
        serializer = ActionSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_action(serializer, **kwargs)
        return Response(serializer.data)

    def perform_batch_activation(self, serializer, **kwargs):
        raise NotImplementedError('`perform_batch_activation()` must be implemented.')

    def perform_batch_action(self, serializer, **kwargs):
        raise NotImplementedError('`perform_batch_action()` must be implemented.')


class IPMACBondStrategyView(NestedViewSetMixin, EngineerPermissionsMixin, ModelViewSet):
    queryset = FirewallIPMACBondStrategy.objects.filter(device__type=Device.FIRE_WALL)
    serializer_class = FirewallIPMACBondStrategySerializer
    serializer_action_classes = {
        'retrieve': FirewallIPMACBondStrategyDetailSerializer
    }

    filter_fields = ('status',)
    permission_classes = (IsConfiEngineer,)

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_bond(self, request, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_bond(serializer, **kwargs)
        return Response(serializer.data)

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_action(self, request, **kwargs):
        serializer = ActionSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_action(serializer, **kwargs)
        return Response(serializer.data)

    @action(methods=['get', 'put'], detail=False, permission_classes=(IsConfiEngineer,))
    def unknown_device_action(self, request, **kwargs):
        unknown_device_action = get_object_or_404(FirewallIPMACUnknownDeviceActionStrategy,
                                                  device_id=self.kwargs['parent_lookup_device'])
        if request.method == 'GET':
            serializer = FirewallIPMACUnknownDeviceActionStrategySerializer(unknown_device_action)
            return Response(serializer.data)
        elif request.method == 'PUT':
            serializer = FirewallIPMACUnknownDeviceActionStrategySerializer(unknown_device_action, data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

    def perform_batch_bond(self, serializer, **kwargs):
        raise NotImplementedError('`perform_batch_bond()` must be implemented.')

    def perform_batch_action(self, serializer, **kwargs):
        raise NotImplementedError('`perform_batch_action()` must be implemented.')


class ModbusStrategyView(NestedViewSetMixin, EngineerPermissionsMixin, ModelViewSet):
    queryset = IndustryProtocolModbusStrategy.objects.filter(device__type=Device.FIRE_WALL)
    serializer_class = IndustryProtocolModbusStrategySerializer
    search_fields = ('rule_id', 'rule_name')
    filter_fields = ('status','action')
    permission_classes = (IsConfiEngineer,)

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_activation(self, request, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_activation(serializer, **kwargs)
        return Response(serializer.data)

    def perform_batch_activation(self, serializer, **kwargs):
        raise NotImplementedError('`perform_batch_activation()` must be implemented.')


class S7StrategyView(NestedViewSetMixin, EngineerPermissionsMixin, ModelViewSet):
    queryset = IndustryProtocolS7Strategy.objects.filter(device__type=Device.FIRE_WALL)
    serializer_class = IndustryProtocolS7StrategySerializer
    filter_fields = ('status','func_type','pdu_type', 'action')
    search_fields = ('id', 'rule_id', 'rule_name')
    permission_classes = (IsConfiEngineer,)

    @action(methods=['put'], detail=False, permission_classes=(IsConfiEngineer,))
    def batch_activation(self, request, **kwargs):
        serializer = ActivationSerialzier(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_batch_activation(serializer, **kwargs)
        return Response(serializer.data)

    def perform_batch_activation(self, serializer, **kwargs):
        raise NotImplementedError('`perform_batch_activation()` must be implemented.')


class TempBaseFirewallStrategyView(BaseFirewallStrategyView):
    queryset = BaseFirewallStrategy.objects.filter(template__type=Device.FIRE_WALL)
    permission_classes = (IsConfiEngineer,)

    def perform_create(self, serializer):
        serializer.save(template_id=self.kwargs['parent_lookup_template'])

    def perform_batch_activation(self, serializer, **kwargs):
        BaseFirewallStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
            status=serializer.validated_data['status'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙模板基础防火墙的统计信息
          response:
            200:
              description: 防火墙设备模板基础防火墙的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙模板基础防火墙数量,
                              "count_enable": 0  /# 启用的防火墙模板基础防火墙数量,
                          }
        """
        temp_id = self.kwargs['parent_lookup_template']
        queryset = self.queryset.filter(template_id=temp_id)
        count_all = queryset.count()
        count_enable = queryset.filter(status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
        )
        return Response(data)


class TempWhiteListStrategyView(WhiteListStrategyView):
    queryset = FirewallWhiteListStrategy.objects.filter(template__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(template_id=self.kwargs['parent_lookup_template'])

    def perform_batch_activation(self, serializer, **kwargs):
        FirewallWhiteListStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
            status=serializer.validated_data['status'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙模板白名单的统计信息
          response:
            200:
              description: 防火墙设备模板白名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙模板白名单数量,
                              "count_enable": 0  /# 启用的防火墙模板白名单数量,
                          }
        """

        temp_id = self.kwargs['parent_lookup_template']
        queryset = self.queryset.filter(template_id=temp_id)
        count_all = queryset.count()
        count_enable = queryset.filter(status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
        )
        return Response(data)


class TempBlackListStrategyView(BlackListStrategyView):
    queryset = FirewallBlackListStrategy.objects.filter(template__type=Device.FIRE_WALL)

    def perform_batch_activation(self, serializer, **kwargs):
        FirewallBlackListStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
            status=serializer.validated_data['status'])

    def perform_batch_action(self, serializer, **kwargs):
        FirewallBlackListStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
            action=serializer.validated_data['action'])

    def perform_create(self, serializer):
        serializer.save(template_id=self.kwargs['parent_lookup_template'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙模板黑名单的统计信息
          response:
            200:
              description: 防火墙设备模板黑名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙模板黑名单数量,
                              "count_enable": 0  /# 启用的防火墙模板黑名单数量,
                          }
        """
        temp_id = self.kwargs['parent_lookup_template']
        queryset = self.queryset.filter(template_id=temp_id)

        count_all = queryset.count()
        count_enable = queryset.filter(status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
        )
        return Response(data)


class TempIPMACBondStrategyView(IPMACBondStrategyView):
    queryset = FirewallIPMACBondStrategy.objects.filter(template__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(template_id=self.kwargs['parent_lookup_template'])

    def perform_batch_bond(self, serializer, **kwargs):
        FirewallIPMACBondStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
            status=serializer.validated_data['status'])

    def perform_batch_action(self, serializer, **kwargs):
        FirewallIPMACBondStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
            action=serializer.validated_data['action'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙模板ip_mac_bond协议的统计信息
          response:
            200:
              description: 防火墙设备模板ip_mac_bond协议的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙模板ip_mac_bond协议数量,
                              "count_enable": 0  /# 启用的防火墙模板ip_mac_bond协议数量,
                          }
        """
        temp_id = self.kwargs['parent_lookup_template']
        queryset = self.queryset.filter(template_id=temp_id)
        count_all = queryset.count()
        count_enable = queryset.filter(status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
        )
        return Response(data)


class TempModbusStrategyView(ModbusStrategyView):
    queryset = IndustryProtocolModbusStrategy.objects.filter(template__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(template_id=self.kwargs['parent_lookup_template'])

    def perform_batch_activation(self, serializer, **kwargs):
        IndustryProtocolModbusStrategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
            status=serializer.validated_data['status'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙模板Modbus协议的统计信息
          response:
            200:
              description: 防火墙设备模板Modbus协议的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙模板Modbus协议数量,
                              "count_enable": 0  /# 启用的防火墙模板Modbus协议数量,
                          }
        """
        temp_id = self.kwargs['parent_lookup_template']
        queryset = self.queryset.filter(template_id=temp_id)
        count_all = queryset.count()
        count_enable = queryset.filter(status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
        )
        return Response(data)


class TempS7StrategyView(S7StrategyView):
    queryset = IndustryProtocolS7Strategy.objects.filter(template__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(template_id=self.kwargs['parent_lookup_template'])

    def perform_batch_activation(self, serializer, **kwargs):
        IndustryProtocolS7Strategy.objects.filter(template_id=kwargs['parent_lookup_template']).update(
            status=serializer.validated_data['status'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙模板S7协议的统计信息
          response:
            200:
              description: 防火墙设备模板S7协议的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙模板S7协议数量,
                              "count_enable": 0  /# 启用的防火墙模板S7协议数量,
                          }
        """
        temp_id = self.kwargs['parent_lookup_template']
        queryset = self.queryset.filter(template_id=temp_id)
        count_all = queryset.count()
        count_enable = queryset.filter(status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
        )
        return Response(data)


class DeviceBaseFirewallStrategyView(BaseFirewallStrategyView):
    queryset = BaseFirewallStrategy.objects.filter(device__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    def perform_batch_activation(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        BaseFirewallStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
            status=serializer.validated_data['status'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙设备基础黑名单的统计信息
          response:
            200:
              description: 防火墙设备基础黑名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙设备基础黑名单协议数量,
                              "count_enable": 0  /# 启用的防火墙设备基础黑名单协议数量,
                              "apply_time": 2020-12-12  /# 策略更新时间 ,
                          }
        """
        device = Device.objects.get(id=self.kwargs['parent_lookup_device'])
        count_all = BaseFirewallStrategy.objects.filter(device=device).count()
        count_enable = BaseFirewallStrategy.objects.filter(device=device, status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
            apply_time=timezone.localtime(device.apply_time)

        )
        return Response(data)


class DeviceWhiteListStrategyView(WhiteListStrategyView):
    queryset = FirewallWhiteListStrategy.objects.filter(device__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    def perform_batch_activation(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        FirewallWhiteListStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
            status=serializer.validated_data['status'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙设备白名单的统计信息
          response:
            200:
              description: 防火墙设备白名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙设备白名单协议数量,
                              "count_enable": 0  /# 启用的防火墙设备白名单协议数量,
                              "apply_time": 2020-12-12  /# 策略更新时间 ,
                          }
        """
        device = Device.objects.get(id=self.kwargs['parent_lookup_device'])
        count_all = FirewallWhiteListStrategy.objects.filter(device=device).count()
        count_enable = FirewallWhiteListStrategy.objects.filter(device=device, status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
            apply_time=timezone.localtime(device.apply_time)

        )
        return Response(data)
        # return Response()


class DeviceBlackListStrategyView(BlackListStrategyView):
    queryset = FirewallBlackListStrategy.objects.filter(device__type=Device.FIRE_WALL)

    def perform_batch_activation(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        FirewallBlackListStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
            status=serializer.validated_data['status'])

    def perform_batch_action(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        FirewallBlackListStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
            action=serializer.validated_data['action'])

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙设备黑名单的统计信息
          response:
            200:
              description: 防火墙设备黑名单的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙设备黑名单协议数量,
                              "count_enable": 0  /# 启用的防火墙设备黑名单协议数量,
                              "apply_time": 2020-12-12  /# 策略更新时间 ,
                          }
        """
        device = Device.objects.get(id=self.kwargs['parent_lookup_device'])
        count_all = FirewallBlackListStrategy.objects.filter(device=device).count()
        count_enable = FirewallBlackListStrategy.objects.filter(device=device, status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
            apply_time=timezone.localtime(device.apply_time)

        )
        return Response(data)


class DeviceIPMACBondStrategyView(IPMACBondStrategyView):
    queryset = FirewallIPMACBondStrategy.objects.filter(device__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    def perform_batch_bond(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        FirewallIPMACBondStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
            status=serializer.validated_data['status'])

    def perform_batch_action(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        FirewallIPMACBondStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
            action=serializer.validated_data['action'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙设备ip_mac_bond协议的统计信息
          response:
            200:
              description: 防火墙设备ip_mac_bond协议的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙设备ip_mac_bond协议数量,
                              "count_enable": 0  /# 启用的防火墙设备ip_mac_bond协议数量,
                              "apply_time": 2020-12-12  /# 策略更新时间 ,
                          }
        """
        device = Device.objects.get(id=self.kwargs['parent_lookup_device'])
        count_all = FirewallIPMACBondStrategy.objects.filter(device=device).count()
        count_enable = FirewallIPMACBondStrategy.objects.filter(device=device, status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
            apply_time=timezone.localtime(device.apply_time)

        )
        return Response(data)


class DeviceModbusStrategyView(ModbusStrategyView):
    queryset = IndustryProtocolModbusStrategy.objects.filter(device__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    def perform_batch_activation(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        IndustryProtocolModbusStrategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
            status=serializer.validated_data['status'])


    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙设备Modbus协议的统计信息
          response:
            200:
              description: 防火墙设备Modbus协议的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙设备Modbus协议数量,
                              "count_enable": 0  /# 启用的防火墙设备Modbus协议数量,
                              "apply_time": 2020-12-12  /# 策略更新时间 ,
                          }
        """
        device = Device.objects.get(id=self.kwargs['parent_lookup_device'])
        count_all = IndustryProtocolModbusStrategy.objects.filter(device=device).count()
        count_enable = IndustryProtocolModbusStrategy.objects.filter(device=device, status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
            apply_time=timezone.localtime(device.apply_time)

        )
        return Response(data)


class DeviceS7StrategyView(S7StrategyView):
    queryset = IndustryProtocolS7Strategy.objects.filter(device__type=Device.FIRE_WALL)

    def perform_create(self, serializer):
        serializer.save(device_id=self.kwargs['parent_lookup_device'])

    def perform_batch_activation(self, serializer, **kwargs):
        device = Device.objects.get(id=kwargs['parent_lookup_device'])
        check_or_update_device_strategy_apply_status(device)
        IndustryProtocolS7Strategy.objects.filter(device_id=kwargs['parent_lookup_device']).update(
            status=serializer.validated_data['status'])

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def statistic_information(self, request, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        get:
          request:
            description: 获取防火墙设备S7协议的统计信息
          response:
            200:
              description: 防火墙设备S7协议的统计信息
              response:
                examples1:
                          {
                              "count_all": 1  /# 总的防火墙设备S7协议数量,
                              "count_enable": 0  /# 启用的防火墙设备S7协议数量,
                              "apply_time": 2020-12-12  /# 策略更新时间 ,
                          }
        """
        device = Device.objects.get(id=self.kwargs['parent_lookup_device'])
        count_all = IndustryProtocolS7Strategy.objects.filter(device=device).count()
        count_enable = IndustryProtocolS7Strategy.objects.filter(device=device, status=1).count()
        data = dict(
            count_all=count_all,
            count_enable=count_enable,
            apply_time=timezone.localtime(device.apply_time)

        )
        return Response(data)


class FirewallSecEventView(BaseLogView):
    queryset = FirewallSecEvent.objects.all()
    serializer_class = FirewallSecEventSerializer
    filter_class = FirewallSecEventFilter

    @action(methods=['get'], detail=False, permission_classes=[IsConfiEngineer])
    def unread(self, request, **kwargs):
        count = FirewallSecEvent.objects.filter(is_read=False).count()
        return Response({'unread': count})


class FirewallSysEventView(BaseLogView):
    queryset = FirewallSysEvent.objects.all()
    serializer_class = FirewallSysEventSerializer
    filter_class = FirewallSysEventFilter
    permission_classes = (IsConfiEngineer,)


class FirewallLogUploadView(APIView):
    # permission_classes = (IsConfiEngineer,)
    permission_classes = ()

    def post(self, request, *args, **kwargs):
        ip = request.META['REMOTE_ADDR']
        firewall = get_object_or_404(Device, ip=ip)
        serializers = FirewallLogUploadSerializer(data=request.data)
        serializers.is_valid(raise_exception=True)
        serializers.save(device_id=firewall.id)
        return Response()

# class FirewallLogUploadView(APIView):
#
#     def post(self, request, *args, **kwargs):
#         # ip = request.META['REMOTE_ADDR']
#         # firewall = get_object_or_404(Device, ip=ip)
#         serializers = FirewallLogUploadSerializer(data=request.data)
#         serializers.is_valid(raise_exception=True)
#         # serializers.save(device_id=firewall.id)
#         serializers.save(device_id=1)
#         return Response()
