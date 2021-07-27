from typing import Dict

from rest_framework import serializers
from django.utils import timezone

from unified_log.models import LogProcessRule, LogProcessTemplate, \
    MANUAL_ADD, AbstractRules
from utils.core.exceptions import CustomError


class LogProcessRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogProcessRule
        fields = ['id', 'name', 'category', 'type', 'brand', 'hardware',
                  'add', 'update_time', 'log_type']


class LogProcessRuleDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogProcessRule
        exclude = []


class LogTemplateSerializer(serializers.ModelSerializer):
    device_count = serializers.IntegerField(label='启用资产数')

    class Meta:
        model = LogProcessTemplate
        fields = ['id', 'name', 'category', 'type', 'brand', 'hardware',
                  'add', 'update_time', 'device_count']



class LogRuleSerializerForTemplate(serializers.ModelSerializer):
    """
    返回模板模板详情的时候，每一条规则都需要以下的字段
    {
        id: 1,
        name: 'xxx',
        pattern: 'xxx',
        example: 'xxx'
    }
    """
    class Meta:
        model = LogProcessRule
        fields = ['id', 'name', 'pattern', 'example']


class LogRuleSerializerForTemplateCreate(serializers.ModelSerializer):
    """
    创建或修改模板的时候，为了保持和详情接口一致的数据结构，所以要变成如下形式
    {
        id: 1
    }
    """
    id = serializers.IntegerField(help_text='规则id', allow_null=True)

    class Meta:
        model = LogProcessRule
        fields = ['id']


class TemplateRulesSerializer(serializers.Serializer):
    """
    详情展示的结构
    {
        kern: {
            id: 1,
            name: 'xxx',
            pattern: 'xxx',
            example: 'xxx'
        },
        user: {
            id: 1,
            name: 'xxx',
            pattern: 'xxx',
            example: 'xxx'
        }
    }
    """
    kern = LogRuleSerializerForTemplate(help_text='内核日志规则')
    user = LogRuleSerializerForTemplate(help_text='用户日志规则')
    mail = LogRuleSerializerForTemplate(help_text='邮件日志规则')
    daemon = LogRuleSerializerForTemplate(help_text='后台程序日志规则')
    auth = LogRuleSerializerForTemplate(help_text='安全认证日志规则')
    syslog = LogRuleSerializerForTemplate(help_text='syslog日志规则')
    lpr = LogRuleSerializerForTemplate(help_text='打印机日志规则')
    cron = LogRuleSerializerForTemplate(help_text='定时任务日志规则')
    ftp = LogRuleSerializerForTemplate(help_text='ftp日志规则')
    authpriv = LogRuleSerializerForTemplate(help_text='登录验证日志规则')
    local0 = LogRuleSerializerForTemplate(help_text='自定义日志规则')
    local1 = LogRuleSerializerForTemplate(help_text='自定义日志规则')
    local2 = LogRuleSerializerForTemplate(help_text='自定义日志规则')
    local3 = LogRuleSerializerForTemplate(help_text='自定义日志规则')
    local4 = LogRuleSerializerForTemplate(help_text='自定义日志规则')
    local5 = LogRuleSerializerForTemplate(help_text='自定义日志规则')
    local6 = LogRuleSerializerForTemplate(help_text='自定义日志规则')
    local7 = LogRuleSerializerForTemplate(help_text='自定义日志规则')


class TemplateRuleCreateSerializer(serializers.Serializer):
    """
    创建或修改模板时的结构
    {
        kern: {
            id: 1,
        },
        user: {
            id: 1,
        }
    }
    """
    kern = LogRuleSerializerForTemplateCreate(
        help_text='内核日志规则', allow_null=True, required=False)
    user = LogRuleSerializerForTemplateCreate(
        help_text='用户日志规则', allow_null=True, required=False)
    mail = LogRuleSerializerForTemplateCreate(
        help_text='邮件日志规则', allow_null=True, required=False)
    daemon = LogRuleSerializerForTemplateCreate(
        help_text='后台程序日志规则', allow_null=True, required=False)
    auth = LogRuleSerializerForTemplateCreate(
        help_text='安全认证日志规则', allow_null=True, required=False)
    syslog = LogRuleSerializerForTemplateCreate(
        help_text='syslog日志规则', allow_null=True, required=False)
    lpr = LogRuleSerializerForTemplateCreate(
        help_text='打印机日志规则', allow_null=True, required=False)
    cron = LogRuleSerializerForTemplateCreate(
        help_text='定时任务日志规则', allow_null=True, required=False)
    ftp = LogRuleSerializerForTemplateCreate(
        help_text='ftp日志规则', allow_null=True, required=False,
    )
    authpriv = LogRuleSerializerForTemplateCreate(
        help_text='登录验证规则', allow_null=True, required=False,
    )
    local0 = LogRuleSerializerForTemplateCreate(
        help_text='自定义日志规则', allow_null=True, required=False)
    local1 = LogRuleSerializerForTemplateCreate(
        help_text='自定义日志规则', allow_null=True, required=False)
    local2 = LogRuleSerializerForTemplateCreate(
        help_text='自定义日志规则', allow_null=True, required=False)
    local3 = LogRuleSerializerForTemplateCreate(
        help_text='自定义日志规则', allow_null=True, required=False)
    local4 = LogRuleSerializerForTemplateCreate(
        help_text='自定义日志规则', allow_null=True, required=False)
    local5 = LogRuleSerializerForTemplateCreate(
        help_text='自定义日志规则', allow_null=True, required=False)
    local6 = LogRuleSerializerForTemplateCreate(
        help_text='自定义日志规则', allow_null=True, required=False)
    local7 = LogRuleSerializerForTemplateCreate(
        help_text='自定义日志规则', allow_null=True, required=False)


class LogTemplateRetrieveSerializer(serializers.ModelSerializer):
    device_count = serializers.SerializerMethodField(help_text='启用资产数')
    rules = TemplateRulesSerializer(help_text='模板规则')

    class Meta:
        model = LogProcessTemplate
        fields = ['id', 'name', 'category', 'type', 'brand', 'hardware',
                  'add', 'update_time', 'device_count', 'mark', 'rules']

    def to_representation(self, instance: LogProcessTemplate):
        instance.rules = AbstractRules(instance)
        return super().to_representation(instance)

    def get_device_count(self, obj: LogProcessTemplate):
        return obj.device_set.count()


class LogTemplateCreateSerializer(serializers.ModelSerializer):
    rules = TemplateRuleCreateSerializer(help_text='模板规则')

    class Meta:
        model = LogProcessTemplate
        fields = ['name', 'category', 'type', 'brand', 'hardware', 'mark',
                  'rules']

    def to_internal_value(self, data: Dict):
        self._validate(data)
        rules = data['rules']
        data = super(LogTemplateCreateSerializer, self).to_internal_value(data)
        data.pop('rules')
        for i in AbstractRules.facilities:
            if not rules.get(i):
                continue
            field = i + '_id'
            data[field] = rules[i].get('id')
        return data

    def to_representation(self, instance: LogProcessTemplate):
        instance.rules = AbstractRules(instance)
        return super().to_representation(instance)

    def create(self, validated_data: Dict):
        validated_data['add'] = MANUAL_ADD
        return super().create(validated_data)

    def _validate(self, attrs: Dict) -> Dict:
        """
        由于name，category，type不重复的校验会早于validate，所有会提前报错
        这里声明方法放在 to_internal_value里调用
        """
        if self.instance:
            # 修改操作时，需要排除自身
            duplicated = LogProcessTemplate.objects.filter(
                name=attrs['name'], category=attrs['category'],
                type=attrs['type']
            ).exclude(id=self.instance.id).exists()
        else:
            duplicated = LogProcessTemplate.objects.filter(
                name=attrs['name'], category=attrs['category'],
                type=attrs['type']
            ).exists()
        if duplicated:
            raise CustomError(
                error_code=CustomError.REPEATED_NAME_CATEGORY_TYPE_ERROR)
        return attrs


class BasicLogSearchSerializer(serializers.Serializer):
    dev_name = serializers.CharField(help_text='资产名称', allow_null=True,
                                     required=False)
    dev_category = serializers.CharField(help_text='资产类别', allow_null=True,
                                         required=False)
    dev_type = serializers.CharField(help_text='资产类型', allow_null=True,
                                     required=False)
    content = serializers.CharField(help_text='日志原始文本', required=False,
                                    allow_null=True)
    page_size = serializers.IntegerField(help_text='分页大小', allow_null=True,
                                         default=50, required=False)

    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass


class LogSearchSerializer(BasicLogSearchSerializer):
    ip = serializers.IPAddressField(help_text='IP地址', allow_null=True,
                                    required=False)
    src_ip = serializers.IPAddressField(help_text='源IP地址', required=False,
                                        allow_null=True)
    src_port = serializers.IntegerField(help_text='源端口', required=False,
                                        allow_null=True)
    dst_ip = serializers.IPAddressField(help_text='目的IP地址', required=False,
                                        allow_null=True)
    dst_port = serializers.IntegerField(help_text='源端口', required=False,
                                        allow_null=True)
    status = serializers.BooleanField(help_text='日志解析结果状态', required=False)
    protocol = serializers.CharField(help_text='协议', required=False,
                                     allow_null=True)
    timestamp_gt = serializers.DateTimeField(
        help_text='日志采集时间，开始2020-10-14T02:51:36+00:00',
        required=False, allow_null=True)
    timestamp_lt = serializers.DateTimeField(
        help_text='日志采集时间，结束2020-10-14T02:51:36+00:00',
        required=False, allow_null=True)
    log_time_gt = serializers.DateTimeField(
        help_text='日志发生时间，开始2020-10-14T02:51:36+00:00',
        required=False, allow_null=True)
    log_time_lt = serializers.DateTimeField(
        help_text='日志发生时间，结束2020-10-14T02:51:36+00:00',
        required=False, allow_null=True)


class RawLogSearchSerializer(BasicLogSearchSerializer):
    timestamp_gt = serializers.DateTimeField(
        help_text='日志采集时间，开始2020-10-14T02:51:36+00:00',
        required=False, allow_null=True)
    timestamp_lt = serializers.DateTimeField(
        help_text='日志采集时间，结束2020-10-14T02:51:36+00:00',
        required=False, allow_null=True)


class ScrollSearchSerializer(LogSearchSerializer):
    """
    使用scroll api的解析日志查询
    """
    scroll_id = serializers.CharField(help_text='滚动加载的分页id,第一次查询传NULL',
                                      required=False, allow_null=True)


class RawScrollSearchSerializer(RawLogSearchSerializer):
    """
    使用scroll api的原始日志查询
    """
    scroll_id = serializers.CharField(help_text='滚动加载的分页id,第一次查询传NULL',
                                      required=False, allow_null=True)


class SearchAfterSerializer(LogSearchSerializer):
    """
    使用search after的解析日志查询
    """
    after = serializers.ListField(
        help_text='滚动加载的参数，首次加载不用传，后续加载传上一次查询的数据最后一项的'
                  'sort字段内容，字段样例[123131312, "1231312"]',
        required=False, allow_null=True,
    )


class RawSearchAfterSerializer(RawLogSearchSerializer):
    """
    使用search after的原始日志查询
    """
    after = serializers.ListField(
        help_text='滚动加载的参数，首次加载不用传，后续加载传上一次查询的数据最后一项的'
                  'sort字段内容，字段样例[123131312, "1231312"]',
        required=False, allow_null=True
    )


class BasicSearchContentSerializer(BasicLogSearchSerializer):
    id = serializers.CharField(help_text='id')
    timestamp = serializers.DateTimeField(help_text='日志采集时间',
                                          default='2020-10-14T02:51:36+00:00')
    sort = serializers.ListField(help_text='排序的参数，可以用于search_after搜索',
                                 required=False, allow_null=True, default=list)


class SearchContentSerializer(BasicSearchContentSerializer):
    """
    解析日志需要展示的字段
    """
    ip = serializers.IPAddressField(help_text='IP地址', allow_null=True,
                                    required=False)
    src_ip = serializers.IPAddressField(help_text='源IP地址', required=False,
                                        allow_null=True)
    src_port = serializers.IntegerField(help_text='源端口', required=False,
                                        allow_null=True)
    dst_ip = serializers.IPAddressField(help_text='目的IP地址', required=False,
                                        allow_null=True)
    dst_port = serializers.IntegerField(help_text='源端口', required=False,
                                        allow_null=True)
    status = serializers.BooleanField(help_text='日志解析结果状态', required=False)
    protocol = serializers.CharField(help_text='协议', required=False,
                                     allow_null=True)
    log_time = serializers.DateTimeField(
        help_text='日志发生时间', default='2020-10-14T02:51:36+00:00')

    def to_internal_value(self, data):
        source = data['_source']
        result = {
            'id': data['_id'],
            'ip': source.get('ip'),
            'src_ip': source.get('src_ip'),
            'dst_ip': source.get('dst_ip'),
            'src_port': source.get('src_port'),
            'dst_port': source.get('dst_port'),
            'dev_name': source.get('dev_name'),
            'dev_category': source.get('dev_category'),
            'dev_type': source.get('dev_type'),
            'status': source.get('status'),
            'content': source.get('content'),
            'timestamp': source['timestamp'],
            'log_time': source.get('log_time'),
            'protocol': source.get('protocol'),
            'sort': data.get('sort'),
        }
        return super().to_internal_value(result)


class RawSearchContentSerializer(BasicSearchContentSerializer):
    """
    原始日志需要展示的字段
    """
    id = serializers.CharField(help_text='id')
    timestamp = serializers.DateTimeField(help_text='日志采集时间',
                                          default='2020-10-14T02:51:36+00:00')

    def to_internal_value(self, data):
        source = data['_source']
        result = {
            'id': data['_id'],
            'dev_name': source.get('dev_name'),
            'dev_category': source.get('dev_category'),
            'dev_type': source.get('dev_type'),
            'status': source.get('status'),
            'content': source.get('content'),
            'timestamp': source['timestamp'],
            'sort': data.get('sort'),
        }
        return result


class ScrollSearchResponse(serializers.Serializer):
    """
    scroll search api返回的格式，主要是scroll_id
    """
    count = serializers.IntegerField(help_text='日志总数')
    scroll_id = serializers.CharField(help_text='滚动加载的分页id')
    results = SearchContentSerializer(many=True)

    def to_internal_value(self, data: Dict):
        """
        从es里查询到的日志内容
        {
          '_scroll_id',
          'hits':
            {
                'total': {'value': xxx},
                'hits': [{'_doc': xx, '_source': {日志内容}}]
            }
        }
        :param data:
        :return:
        """
        results = SearchContentSerializer(data=data['hits']['hits'], many=True)
        results.is_valid(raise_exception=True)
        new_data = {
            'scroll_id': data.get('_scroll_id'),
            'count': data['hits']['total']['value'],
            'results': results.data,
        }

        return new_data


class SearchAfterResponse(serializers.Serializer):
    """
    search after api返回的格式，主要是after参数
    """
    count = serializers.IntegerField(help_text='日志总数')
    after = serializers.ListField(help_text='滚动加载的参数')
    results = SearchContentSerializer(many=True)

    def to_internal_value(self, data):
        results = SearchContentSerializer(data=data['hits']['hits'], many=True)
        results.is_valid(raise_exception=True)
        new_data = {
            'count': data['hits']['total']['value'],
            'results': results.data,
        }
        if results.data:
            new_data['after'] = results.data[-1]['sort']
        else:
            new_data['after'] = None

        return new_data


class RawScrollSearchResponse(serializers.Serializer):
    """
    scroll search api返回的格式，主要是scroll_id
    """
    count = serializers.IntegerField(help_text='日志总数')
    scroll_id = serializers.CharField(help_text='滚动加载的分页id')
    results = RawSearchContentSerializer(many=True)

    def to_internal_value(self, data: Dict):
        """
        从es里查询到的日志内容
        {
          '_scroll_id',
          'hits':
            {
                'total': {'value': xxx},
                'hits': [{'_doc': xx, '_source': {日志内容}}]
            }
        }
        :param data:
        :return:
        """
        results = RawSearchContentSerializer(data=data['hits']['hits'],
                                             many=True)
        results.is_valid(raise_exception=True)
        new_data = {
            'scroll_id': data.get('_scroll_id'),
            'count': data['hits']['total']['value'],
            'results': results.data,
        }

        return new_data


class RawSearchAfterResponse(serializers.Serializer):
    """
    search after api返回的格式，主要是after参数
    """
    count = serializers.IntegerField(help_text='日志总数')
    after = serializers.ListField(help_text='滚动加载的参数', allow_null=True)
    results = RawSearchContentSerializer(many=True)

    def to_internal_value(self, data):
        results = RawSearchContentSerializer(data=data['hits']['hits'],
                                             many=True)
        results.is_valid(raise_exception=True)
        new_data = {
            'count': data['hits']['total']['value'],
            'results': results.data,
        }
        if results.data:
            new_data['after'] = results.data[-1]['sort']
        else:
            new_data['after'] = None

        return new_data