from django.db.models import Count
from django.utils.decorators import method_decorator
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet

from snmp.filters import SNMPRuleFilter, SNMPTemplateFilter
from snmp.serializers import *
from utils.core.exceptions import CustomError
from utils.core.mixins import MultiActionConfViewSetMixin
from utils.core.permissions import IsConfiEngineer


class SNMPRuleView(ReadOnlyModelViewSet):
    serializer_class = SNMPRuleSerializer
    queryset = SNMPRule.objects.all()
    permission_classes = (IsConfiEngineer,)
    filter_class = SNMPRuleFilter

    @method_decorator(swagger_auto_schema(
        operation_description='获取性能监控规则列表，如果url里的传了page参数，则返回'
                              '分页后的结果，如果不传page参数，则返回所有的规则',
        operation_summary='获取性能监控规则列表'
    ))
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        if request.query_params.get('page'):
            # 带分页参数的请求走分页逻辑，否则返回全部
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class SNMPTemplateView(MultiActionConfViewSetMixin, ModelViewSet):
    serializer_class = SNMPTemplateSerializer
    queryset = SNMPTemplate.objects.all()
    permission_classes = (IsConfiEngineer,)
    serializer_action_classes = {
        'retrieve': SNMPTemplateRetrieveSerializer,
        'list': SNMPTemplateListSerializer,
    }
    filter_class = SNMPTemplateFilter
    ordering_fields = ('device_count', 'update_time')

    @method_decorator(swagger_auto_schema(
        operation_description='获取SNMP模板列表，如果url里的传了page参数，则返回'
                              '分页后的结果，如果不传page参数，则返回所有的模板',
        operation_summary='获取性能监控模板列表'
    ))
    def list(self, request, *args, **kwargs):
        self.queryset = self.get_queryset().annotate(
            device_count=Count('snmpsetting'))
        queryset = self.filter_queryset(self.get_queryset())

        if request.query_params.get('page'):
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        template = serializer.save()
        headers = self.get_success_headers(serializer.data)
        data = serializer.data
        data['id'] = template.id
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance: SNMPTemplate = self.get_object()
        if instance.add == SNMPTemplate.SYSTEM_ADD:
            raise CustomError(
                {'error': CustomError.UN_ALLOWED_TO_EDIT_SYSTEM_TEMPLATE})
        serializer = self.get_serializer(instance, data=request.data,
                                         partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.add == SNMPTemplate.SYSTEM_ADD:
            raise CustomError(
                {'error': CustomError.UN_ALLOWED_TO_DELETE_SYSTEM_TEMPLATE})
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
