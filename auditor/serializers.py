from rest_framework import fields
from rest_framework import serializers

from auditor.models import AuditWhiteListStrategy, AuditBlackListStrategy, AuditIPMACBondStrategy, AuditSecAlert, \
    AuditSysAlert, AuditLog
from base_app.models import StrategyTemplate, Device


def convert_rule(rule):
    """
    Try to convert rule value to integer.
    :param rule: rule with value in string type.
    :return:
    """
    for field, value in rule.copy().items():
        if value is None:
            rule.pop(field)
        elif isinstance(value, dict):
            convert_rule(value)
        elif isinstance(value, list):
            for i in range(len(value[0])):
                if not isinstance(value[0][i], (int, float)):
                    try:
                        rule[field][0][i] = int(value[0][i], 0)
                    except (ValueError, TypeError):
                        pass

            for i in range(len(value[1])):
                if not isinstance(value[1][i][0], (int, float)):
                    try:
                        rule[field][1][i][0] = int(value[1][i][0], 0)
                    except (ValueError, TypeError):
                        pass
                if not isinstance(value[1][i][1], (int, float)):
                    try:
                        rule[field][1][i][1] = int(value[1][i][1], 0)
                    except (ValueError, TypeError):
                        pass
        elif isinstance(value, (int, float)):
            # Keep consistent format.
            rule[field] = [[value], []]
        else:
            try:
                rule[field] = [[int(value, 0)], []]
            except (ValueError, TypeError):
                rule[field] = [[value], []]


class CheckTypeMixin(object):

    def create(self, validated_data):
        """
        创建白名单路径`auditor/device(template)/{id}/whitelist/` 使用了drf-extension,
        但是在post新的策略时，无法校验该device（或template）是否是auditor类，
        这里就是校验device（或template）的类型
        """
        device_id = validated_data.get('device_id', None)
        try:
            if device_id:
                device = Device.objects.get(id=validated_data['device_id'])
                if device.type != Device.AUDITOR:
                    raise serializers.ValidationError("not an auditor device")
            else:
                template = StrategyTemplate.objects.get(id=validated_data['template_id'])
                if template.type != Device.AUDITOR:
                    raise serializers.ValidationError("not an auditor template")
        except (StrategyTemplate.DoesNotExist, Device.DoesNotExist )as e:
            raise serializers.ValidationError(str(e))

        return super(CheckTypeMixin, self).create(validated_data)


# Valid port string: '12,34,56:59' maps list [[12,12],[34,34],[56,59]]
class PortListField(fields.ListField):
    child = fields.ListField(child=fields.IntegerField(min_value=1, max_value=65535), min_length=2, max_length=2)

    def to_internal_value(self, data):
        if not data:
            return None
        data = str(data)
        # data_tmp = data
        # data = []
        # for i in data_tmp.split(','):
        #     if ':' not in i:
        #         data.append([i.strip()]*2)
        #     else:
        #         data.append([j.strip() for j in i.split(':')])
        data = [[i.strip()]*2 if ':' not in i else [j.strip() for j in i.split(':')] for i in data.split(',')]
        tmp = super(PortListField, self).to_internal_value(data)
        data = []
        for x, y in tmp:
            if x <= y:
                data.append([x, y])
            else:
                data.append([y, x])
        return data

    def to_representation(self, obj):
        # obj = super(PortListField, self).to_representation(obj)
        if not obj:
            return ''
        # ports_list = []
        # for i in obj:
        #     if i[0] == i[1]:
        #         ports_list.append(str(i[0]))
        #     else:
        #         ports_list.append(':'.join([str(i[0]), str(i[1])]))
        # ports_string = ','.join(ports_list)
        ports_string = ','.join([str(i[0]) if i[0] == i[1] else ':'.join([str(i[0]), str(i[1])]) for i in obj])
        return ports_string


class ExtraFieldModelSerializer(serializers.ModelSerializer):
    """
    重写get_field_names，以便可以在使用fields = __all__的时候添加额外的field
    而不用将所有的field都显式的写出来
    可以在Meta中添加extra_fields属性
    """
    def get_field_names(self, declared_fields, info):
        expanded_fields = super(ExtraFieldModelSerializer, self).get_field_names(declared_fields, info)

        if getattr(self.Meta, 'extra_fields', None):
            expanded_fields.extend(self.Meta.extra_fields)
        return expanded_fields


class ActivationSerialzier(serializers.Serializer):
    is_active = serializers.BooleanField(required=False)


class BatchAuditorSerialzier(serializers.Serializer):
    ids = serializers.ListField(child=serializers.IntegerField(), required=False, allow_null=True, allow_empty=True)
    is_active = serializers.BooleanField(required=False)


class AuditWhiteListStrategySerializer(CheckTypeMixin, serializers.ModelSerializer):
    src_ports = PortListField(required=False, allow_null=True, allow_empty=True)
    dst_ports = PortListField(required=False, allow_null=True, allow_empty=True)

    class Meta:
        model = AuditWhiteListStrategy
        fields = ('id', 'level', 'name', 'src_ip', 'src_ports', 'dst_ip', 'dst_ports',
                  'protocol', 'rule', 'is_active', 'is_learned', 'created_time')

    def validate(self, data):
        if data.get('rule'):
            if not isinstance(data['rule'], list):
                # Keep consistent format. you can put several rule in 1 ICSRule.
                data['rule'] = [data['rule']]
            try:
                for rule in data['rule']:
                    convert_rule(rule)
            except (TypeError, AttributeError, KeyError, IndexError):
                raise serializers.ValidationError('Invalid ICS rule value format! Example: [[1,3,5],[[7,8],[10,14]]]')

        return data


class AuditBlackListStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = AuditBlackListStrategy
        fields = ('id', 'level', 'name', 'cnnvd', 'cve', 'source', 'publish_date', 'is_active')


class AuditBlackListStrategyApplySerializer(serializers.ModelSerializer):

    class Meta:
        model = AuditBlackListStrategy
        exclude = ('id',)


class AuditBlackListStrategyDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuditBlackListStrategy
        fields = '__all__'


class AuditIPMACBondSerializer(serializers.Serializer):
    ip_mac_bond = serializers.BooleanField()


class AuditorIPMACBondStrategySerializer(serializers.ModelSerializer):

    # device = serializers.RelatedField(read_only=True)

    class Meta:
        model = AuditIPMACBondStrategy
        fields = ('id', 'name', 'ip', 'mac', 'ip_mac_bond', )
        # validators = [
        #     UniqueTogetherValidator(
        #         queryset=AuditIPMACBondStrategy.objects.all(),
        #         fields=('device', 'ip',),
        #         message='xxxxxx'
        #     )
        # ]

    # def is_valid(self, raise_exception=False):
    #     # This implementation is the same as the default,
    #     # except that we use lists, rather than dicts, as the empty case.
    #     assert hasattr(self, 'initial_data'), (
    #         'Cannot call `.is_valid()` as no `data=` keyword argument was '
    #         'passed when instantiating the serializer instance.'
    #     )
    #
    #     if not hasattr(self, '_validated_data'):
    #         try:
    #             self._validated_data = self.run_validation(self.initial_data)
    #         except serializers.ValidationError as exc:
    #             self._validated_data = []
    #             self._errors = exc.detail
    #         else:
    #             self._errors = []
    #
    #     if self._errors and raise_exception:
    #         if 'already exists' in str(self._errors.get('ip')):
    #             raise CustomError({'error': '1008'})
    #         if 'already exists' in str(self._errors.get('mac')):
    #             raise CustomError({'error': '1009'})
    #         raise serializers.ValidationError(self.errors)
    #
    #     return not bool(self._errors)


class AuditorIPMACBondStrategyDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = AuditIPMACBondStrategy
        fields = ('id', 'name', 'ip', 'mac', 'ip_mac_bond', 'created_time')


class AuditSecAlertUploadListSerializer(serializers.ListSerializer):

    def create(self, validated_data):
        sec_alerts = [AuditSecAlert(**item) for item in validated_data]
        return AuditSecAlert.objects.bulk_create(sec_alerts)


class AuditSecAlertUploadSerializer(serializers.ModelSerializer):
    """
    用于上传AuditSecAlert信息的序列化类，因为平台端有些字段和审计端定义不一致，需要重写部分字段
    """
    # read_at = serializers.DateTimeField(source='read_time')

    class Meta:
        list_serializer_class = AuditSecAlertUploadListSerializer
        model = AuditSecAlert
        fields = '__all__'


class AuditSecAlertSerializer(ExtraFieldModelSerializer):
    """
    AuditSecurityAlert信息序列化类
    """
    dev_name = serializers.SerializerMethodField()

    class Meta:
        model = AuditSecAlert
        fields = '__all__'
        extra_fields = ('dev_name',)

    def get_dev_name(self, obj):
        return obj.device.name


class AuditSecAlertNoticeSerializer(serializers.ModelSerializer):

    device = serializers.SlugRelatedField(read_only=True, slug_field='name')
    device_type = serializers.SlugRelatedField(read_only=True, slug_field='type', source='device')
    occurred_time = serializers.DateTimeField(source='last_at')

    class Meta:
        model = AuditSecAlert
        fields = ('id', 'device', 'occurred_time', 'content', 'device_type', 'level', 'category')


class AuditSysAlertUploadListSerializer(serializers.ListSerializer):

    def create(self, validated_data):
        sys_alerts = [AuditSysAlert(**item) for item in validated_data]
        return AuditSysAlert.objects.bulk_create(sys_alerts)


class AuditSysAlertUploadSerializer(serializers.ModelSerializer):
    """
    用于上传SystemAlert信息的序列化类，因为平台端有些字段和审计端定义不一致，需要重写部分字段
    """
    occurred_at = serializers.DateTimeField(source='occurred_time')

    class Meta:
        list_serializer_class = AuditSysAlertUploadListSerializer
        model = AuditSysAlert
        fields = '__all__'


class AuditSysAlertSerializer(ExtraFieldModelSerializer):
    """
    SystemAlert信息序列化类
    """
    dev_name = serializers.SerializerMethodField()

    class Meta:
        model = AuditSysAlert
        fields = '__all__'
        extra_fields = ('dev_name',)

    def get_dev_name(self, obj):
        return obj.device.name


class AuditSysAlertNoticeSerializer(serializers.ModelSerializer):

    device = serializers.SlugRelatedField(read_only=True, slug_field='name')
    device_type = serializers.SlugRelatedField(read_only=True, slug_field='type', source='device')

    class Meta:
        model = AuditSysAlert
        fields = ('id', 'device', 'occurred_time', 'content', 'device_type', 'level', 'category')


class AuditLogUploadListSerializer(serializers.ListSerializer):

    def create(self, validated_data):
        logs = [AuditLog(**item) for item in validated_data]
        return AuditLog.objects.bulk_create(logs)


class AuditLogUploadSerializer(serializers.ModelSerializer):
    """
    用于上传Log信息的序列化类，因为平台端有些字段和审计端定义不一致，需要重写部分字段
    """
    occurred_at = serializers.DateTimeField(source='occurred_time')

    class Meta:
        list_serializer_class = AuditLogUploadListSerializer
        model = AuditLog
        fields = '__all__'


class AuditLogSerializer(ExtraFieldModelSerializer):
    """
    Log信息序列化类
    """
    dev_name = serializers.SerializerMethodField()

    class Meta:
        model = AuditSysAlert
        fields = '__all__'
        extra_fields = ('dev_name',)

    def get_dev_name(self, obj):
        return obj.device.name

#
# class AuditLogSerializer(ExtraFieldModelSerializer):
#     """
#     Log信息序列化类
#     """
#     dev_name = serializers.SerializerMethodField()
#
#     class Meta:
#         model = AuditLog
#         fields = '__all__'
#         extra_fields = ('dev_name',)
#
#     def get_dev_name(self, obj):
#         return obj.device.name


class ApplyStrategySerializer(serializers.Serializer):
    """
    统一管理平台下发的策略信息序列化类
    """
    whitelist = AuditWhiteListStrategySerializer(many=True, required=False)
    blacklist = AuditBlackListStrategyApplySerializer(many=True, required=False)
    device = AuditorIPMACBondStrategySerializer(many=True, required=False)

    def create(self, validated_data):

        if 'device' in validated_data:
            device_items = validated_data['device']
            device_id = validated_data.get('device_id')
            if device_id:
                r = []
                for i in validated_data['device']:
                    i['device_id'] = device_id
                    r.append(i)
                device_items = r

            devices = [AuditIPMACBondStrategy(**item) for item in device_items]
            AuditIPMACBondStrategy.objects.bulk_create(devices)

        if 'whitelist' in validated_data:
            whitelist_items = validated_data['whitelist']

            device_id = validated_data.get('device_id')
            if device_id:
                r = []
                for i in validated_data['whitelist']:
                    i['device_id'] = device_id
                    r.append(i)
                whitelist_items = r

            whitelists = [AuditWhiteListStrategy(**item) for item in whitelist_items]
            AuditWhiteListStrategy.objects.bulk_create(whitelists)

        if 'blacklist' in validated_data:
            blacklist_items = validated_data['blacklist']

            device_id = validated_data.get('device_id')
            if device_id:
                r = []
                for i in validated_data['blacklist']:
                    i['device_id'] = device_id
                    r.append(i)
                blacklist_items = r

            blacklists = [AuditBlackListStrategy(**item) for item in blacklist_items]
            AuditBlackListStrategy.objects.bulk_create(blacklists)

        return validated_data

