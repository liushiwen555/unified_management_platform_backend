from django.db.models import Count
from django.utils.decorators import method_decorator
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from elasticsearch.exceptions import NotFoundError, RequestError
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ReadOnlyModelViewSet, ModelViewSet

from unified_log.filters import *
from unified_log.models import SYSTEM_ADD
from unified_log.serializers import *
from utils.core.exceptions import CustomError
from utils.core.mixins import MultiActionConfViewSetMixin
from utils.core.permissions import IsConfiEngineer


class LogRuleView(MultiActionConfViewSetMixin, ReadOnlyModelViewSet):
    """
    日志解析规则的视图，只允许用户查看列表和详情
    """
    queryset = LogProcessRule.objects.all()
    serializer_class = LogProcessRuleSerializer
    serializer_action_classes = {
        'list': LogProcessRuleSerializer,
        'retrieve': LogProcessRuleDetailSerializer,
    }
    permission_classes = (IsConfiEngineer,)
    filter_class = LogRuleFilter

    @method_decorator(swagger_auto_schema(
        operation_description='获取日志解析规则列表，如果url里的传了page参数，则返回'
                              '分页后的结果，如果不传page参数，则返回所有的规则',
        operation_summary='获取日志解析规则列表'
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


class LogTemplateView(MultiActionConfViewSetMixin, ModelViewSet):
    """
    日志解析模板的视图，允许用户增删改查
    """
    queryset = LogProcessTemplate.objects.all()
    serializer_class = LogTemplateSerializer
    serializer_action_classes = {
        'list': LogTemplateSerializer,
        'retrieve': LogTemplateRetrieveSerializer,
        'create': LogTemplateCreateSerializer,
        'update': LogTemplateCreateSerializer,
    }
    permission_classes = (IsConfiEngineer,)
    filter_class = LogTemplateFilter
    ordering_fields = ('device_count', 'update_time')

    @method_decorator(swagger_auto_schema(
        operation_description='获取日志模板列表，如果url里的传了page参数，则返回'
                              '分页后的结果，如果不传page参数，则返回所有的模板',
        operation_summary='获取日志模板列表'
    ))
    def list(self, request, *args, **kwargs):
        self.queryset = self.get_queryset().annotate(device_count=Count('device'))
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
        data = serializer.data
        headers = self.get_success_headers(serializer.data)
        data['id'] = template.id
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance: LogProcessTemplate = self.get_object()
        if instance.add == SYSTEM_ADD:
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
        if instance.add == SYSTEM_ADD:
            raise CustomError(
                {'error': CustomError.UN_ALLOWED_TO_DELETE_SYSTEM_TEMPLATE})
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


scroll_search_response = openapi.Response('日志查询结果', ScrollSearchResponse)
search_after_response = openapi.Response('日志查询结果', SearchAfterResponse)
raw_scroll_search_response = openapi.Response('原始日志查询结果',
                                              RawScrollSearchResponse)
raw_search_after_response = openapi.Response('原始日志查询结果',
                                              RawSearchAfterResponse)


class LogSearchView(APIView):
    permission_classes = (IsAuthenticated,)
    filter_class = LogSearchFilter
    serializer_class = ScrollSearchResponse

    def get_query(self, query: Dict, raw=False):
        if not raw:
            query['status'] = True
        search = self.filter_class(**query)
        search.sort('-timestamp')
        search_query = search.get_query()
        size = query.get('page_size', 10)
        search_query.update({'size': size})
        return search_query

    @method_decorator(swagger_auto_schema(
        request_body=ScrollSearchSerializer,
        responses={'200': scroll_search_response},
        operation_description='解析日志查询',
        operation_summary='解析日志查询,使用了scroll查询',
    ))
    def post(self, request):
        serializer = ScrollSearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        scroll_id = data.get('scroll_id')
        query = self.get_query(data)
        try:
            res = BaseDocument.scroll(scroll_id)
        except (NotFoundError, ValueError, RequestError):
            res = BaseDocument.search_with_scroll(query)
        result = self.serializer_class(data=res)
        result.is_valid(raise_exception=True)
        return Response(result.data)


class RawLogSearchView(LogSearchView):
    serializer_class = RawScrollSearchResponse

    @method_decorator(swagger_auto_schema(
        request_body=RawScrollSearchSerializer,
        responses={'200': raw_scroll_search_response},
        operation_description='原始日志查询',
        operation_summary='原始日志查询，使用了scroll查询',
    ))
    def post(self, request):
        serializer = RawScrollSearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        scroll_id = data.get('scroll_id')
        query = self.get_query(data, raw=True)
        try:
            res = BaseDocument.scroll(scroll_id)
        except (NotFoundError, ValueError, RequestError):
            res = BaseDocument.search_with_scroll(query)
        result = self.serializer_class(data=res)
        result.is_valid(raise_exception=True)
        return Response(result.data)


class LogSearchAfterView(APIView):
    permission_classes = (IsAuthenticated, )
    filter_class = LogSearchFilter
    serializer_class = SearchAfterResponse

    def get_query(self, query: Dict, raw=False):
        if not raw:
            query['status'] = True
        search = self.filter_class(**query)
        search_query = search.get_query()
        search_query.update({'size': query['page_size']})
        return search_query

    @method_decorator(swagger_auto_schema(
        request_body=SearchAfterSerializer,
        responses={'200': search_after_response},
        operation_description='解析日志查询,初次查询时候不带after参数，后续查询要使用'
                              '上一查询返回的after参数',
        operation_summary='解析日志查询，使用了search_after查询',
    ))
    def post(self, request):
        serializer = SearchAfterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        query = self.get_query(data)
        res = BaseDocument.search_after(query, after=data.get('after'))
        result = self.serializer_class(data=res)
        result.is_valid(raise_exception=True)
        return Response(result.data)


class RawSearchAfterView(LogSearchAfterView):
    serializer_class = RawSearchAfterResponse

    @method_decorator(swagger_auto_schema(
        request_body=RawSearchAfterSerializer,
        responses={'200': raw_search_after_response},
        operation_description='解析日志查询,初次查询时候不带after参数，后续查询要使用'
                              '上一查询返回的after参数',
        operation_summary='原始日志查询,使用了search_after查询',
    ))
    def post(self, request):
        serializer = RawSearchAfterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.data
        query = self.get_query(data, raw=True)
        res = BaseDocument.search_after(query, after=data.get('after'))
        result = self.serializer_class(data=res)
        result.is_valid(raise_exception=True)
        return Response(result.data)
