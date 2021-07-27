from rest_framework import serializers

from base_app.models import StrategyTemplate, Device
from firewall.models import FirewallWhiteListStrategy, FirewallBlackListStrategy, FirewallIPMACBondStrategy, \
    BaseFirewallStrategy, ConfStrategy, IndustryProtocolDefaultConfStrategy, IndustryProtocolOPCStrategy, \
    IndustryProtocolModbusStrategy, IndustryProtocolS7Strategy, FirewallSecEvent, FirewallSysEvent, \
    FirewallLearnedWhiteListStrategy, FirewallIPMACUnknownDeviceActionStrategy
from log.models import DeviceAllAlert
from utils.protocol_num_convert import proto_2_num


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
                if device.type != Device.FIRE_WALL:
                    raise serializers.ValidationError("not an firewall device")
            else:
                template = StrategyTemplate.objects.get(id=validated_data['template_id'])
                if template.type != Device.FIRE_WALL:
                    raise serializers.ValidationError("not an firewall template")
        except (StrategyTemplate.DoesNotExist, Device.DoesNotExist )as e:
            raise serializers.ValidationError(str(e))

        return super(CheckTypeMixin, self).create(validated_data)


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
    status = serializers.IntegerField()


class ActionSerialzier(serializers.Serializer):
    action = serializers.IntegerField()


class BaseFirewallStrategySerializer(CheckTypeMixin, serializers.ModelSerializer):

    class Meta:
        model = BaseFirewallStrategy
        fields = ('id', 'rule_id', 'rule_name', 'src_ip', 'dst_ip',
                  'src_port', 'dst_port', 'created_time', 'protocol', 'logging', 'action', 'status',)


class BaseFirewallStrategyApplySerializer(serializers.ModelSerializer):

    ruleid = serializers.IntegerField(source='rule_id')
    rulename = serializers.CharField(source='rule_name')
    srcip = serializers.IPAddressField(source='src_ip')
    srcport = serializers.IntegerField(source='src_port', max_value=65535, min_value=1)
    dstip = serializers.IPAddressField(source='dst_ip')
    dstport = serializers.IntegerField(source='dst_port', max_value=65535, min_value=1)
    protocolid = serializers.SerializerMethodField()

    class Meta:
        model = BaseFirewallStrategy
        fields = ('ruleid', 'rulename', 'srcip', 'dstip',
                  'srcport', 'dstport', 'protocolid', 'logging', 'action', 'status',)

    def get_protocolid(self, obj):
        return proto_2_num(obj.protocol)

    def to_representation(self, instance):

        ret = super(BaseFirewallStrategyApplySerializer, self).to_representation(instance)
        if ret['dstport'] is None:
            ret['dstport'] = ''
        if ret['srcport'] is None:
            ret['srcport'] = ''
        return ret


class FirewallWhiteListStrategySerializer(CheckTypeMixin, serializers.ModelSerializer):

    class Meta:
        model = FirewallWhiteListStrategy
        fields = ('id', 'rule_id', 'rule_name', 'src_ip', 'dst_ip',
                  'src_port', 'dst_port', 'protocol', 'logging', 'status', 'created_time')


class FirewallWhiteListStrategyApplySerializer(serializers.ModelSerializer):

    ruleid = serializers.IntegerField(source='rule_id')
    rulename = serializers.CharField(source='rule_name')
    srcip = serializers.IPAddressField(source='src_ip')
    srcport = serializers.IntegerField(source='src_port', max_value=65535, min_value=1)
    dstip = serializers.IPAddressField(source='dst_ip')
    dstport = serializers.IntegerField(source='dst_port', max_value=65535, min_value=1)
    protocolid = serializers.SerializerMethodField()

    class Meta:
        model = FirewallWhiteListStrategy
        fields = ('ruleid', 'rulename', 'srcip', 'dstip',
                  'srcport', 'dstport', 'protocolid', 'logging', 'status',)

    def get_protocolid(self, obj):
        return proto_2_num(obj.protocol)


class FirewallLearnedWhiteListStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = FirewallLearnedWhiteListStrategy
        fields = ('id', 'sid', 'rule_name', 'src_ip', 'dst_ip', 'src_mac', 'dst_mac',
                  'proto_name', 'fields', 'level', 'created_time', 'action', 'status')


class FirewallLearnedWhiteListUploadListSerializer(serializers.ListSerializer):

    def create(self, validated_data):
        whitelists = [FirewallLearnedWhiteListStrategy(**item) for item in validated_data]
        return FirewallLearnedWhiteListStrategy.objects.bulk_create(whitelists)


class FirewallLearnedWhiteListUploadSerializer(serializers.ModelSerializer):

    id = serializers.IntegerField(source='sid')
    filterfields = serializers.CharField(source='filter_fields')
    riskLevel = serializers.IntegerField(source='level')
    ruleName = serializers.CharField(source='rule_name')
    srcIp = serializers.IPAddressField(source='src_ip')
    dstIp = serializers.IPAddressField(source='dst_ip')
    srcMac = serializers.CharField(source='src_mac', allow_blank=True)
    dstMac = serializers.CharField(source='dst_mac', allow_blank=True)
    # creatTime = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', source='created_time')
    creatTime = serializers.DateTimeField(source='created_time', input_formats=['%Y-%m-%d-%H:%M:%S'])
    protoName = serializers.CharField(source='proto_name')

    class Meta:
        list_serializer_class = FirewallLearnedWhiteListUploadListSerializer
        model = FirewallLearnedWhiteListStrategy
        fields = ('id', 'fields', 'body', 'filterfields', 'riskLevel', 'ruleName', 'srcIp', 'dstIp', 'srcMac', 'dstMac',
                  'proto', 'tmp_action', 'protoName', 'creatTime', 'action')
        # fields = ('sid', 'filterfields', 'level')


class FirewallWhiteListStrategyLearnSerializer(serializers.Serializer):

    start = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    dur = serializers.IntegerField()


class FirewallBlackListStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = FirewallBlackListStrategy
        fields = ('id', 'name', 'level', 'publish_date', 'action', 'status')


class FirewallBlackListStrategyDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = FirewallBlackListStrategy
        fields = '__all__'


class FirewallIPMACBondSerializer(serializers.Serializer):
    status = serializers.IntegerField()


class FirewallIPMACBondStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = FirewallIPMACBondStrategy
        fields = ('id', 'device_name', 'ip', 'mac', 'status', 'action')


class FirewallIPMACBondStrategyDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = FirewallIPMACBondStrategy
        fields = ('id', 'device_name', 'ip', 'mac', 'status', 'action', 'created_time')


class FirewallIPMACUploadListSerializer(serializers.ListSerializer):

    def create(self, validated_data):
        ip_macs = [FirewallIPMACBondStrategy(**item) for item in validated_data]
        return FirewallIPMACBondStrategy.objects.bulk_create(ip_macs)


class FirewallIPMACBondStrategyUploadSerializer(serializers.ModelSerializer):

    enabled = serializers.IntegerField(source='status')

    class Meta:
        model = FirewallIPMACBondStrategy
        list_serializer_class = FirewallIPMACUploadListSerializer
        fields = ('device_name', 'ip', 'mac', 'enabled')


class FirewallIPMACUnknownDeviceActionStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = FirewallIPMACUnknownDeviceActionStrategy
        fields = ('action', )


class FirewallIPMACBondStrategyApplySerializer(serializers.ModelSerializer):

    class Meta:
        model = FirewallIPMACBondStrategy
        fields = ('device_name', 'ip', 'mac', 'status', 'action')


class ConfStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = ConfStrategy
        fields = ('run_mode', 'default_filter', 'DPI')


class IndustryProtocolDefaultConfStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = IndustryProtocolDefaultConfStrategy
        fields = ('OPC_default_action', 'modbus_default_action')


class IndustryProtocolOPCStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = IndustryProtocolOPCStrategy
        fields = ('is_read_open', 'read_action', 'is_write_open', 'write_action')


class IndustryProtocolModbusStrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = IndustryProtocolModbusStrategy
        fields = ('id', 'rule_id', 'rule_name', 'func_code',
                  'reg_start', 'reg_end', 'length', 'reg_value', 'logging', 'action', 'status')


class IndustryProtocolModbusStrategyApplySerializer(serializers.ModelSerializer):
    ruleid = serializers.IntegerField(source='rule_id')
    rulename = serializers.CharField(source='rule_name')
    functionCode = serializers.CharField(source='func_code')
    startAddress = serializers.CharField(source='reg_start')
    endAddress = serializers.CharField(source='reg_end')
    addressLen = serializers.CharField(source='length')
    registerVal = serializers.CharField(source='reg_value')

    class Meta:
        model = IndustryProtocolModbusStrategy
        fields = ('ruleid', 'rulename', 'functionCode', 'startAddress', 'endAddress',
                  'addressLen', 'registerVal', 'logging', 'action', 'status')


class IndustryProtocolS7StrategySerializer(serializers.ModelSerializer):

    class Meta:
        model = IndustryProtocolS7Strategy
        fields = ('id', 'rule_id', 'rule_name', 'func_type', 'pdu_type', 'action', 'status')


class IndustryProtocolS7StrategyApplySerializer(serializers.ModelSerializer):
    ruleid = serializers.IntegerField(source='rule_id')
    rulename = serializers.CharField(source='rule_name')
    functionType = serializers.CharField(source='func_type')
    pduType = serializers.CharField(source='pdu_type')

    class Meta:
        model = IndustryProtocolS7Strategy
        fields = ('ruleid', 'rulename', 'functionType', 'pduType', 'action', 'status')


class FirewallSecEventSerializer(ExtraFieldModelSerializer):
    """
    FirewallSecEvent信息序列化类
    """
    dev_name = serializers.SerializerMethodField()

    class Meta:
        model = FirewallSecEvent
        fields = '__all__'
        extra_fields = ('dev_name',)

    def get_dev_name(self, obj):
        return obj.device.name


class FirewallSecEventNoticeSerializer(serializers.ModelSerializer):

    device = serializers.SlugRelatedField(read_only=True, slug_field='name')
    device_type = serializers.SlugRelatedField(read_only=True, slug_field='type', source='device')

    class Meta:
        model = FirewallSecEvent
        fields = ('id', 'device', 'occurred_time', 'content', 'device_type', 'level')


class FirewallSysEventSerializer(ExtraFieldModelSerializer):
    """
    SystemAlert信息序列化类
    """
    dev_name = serializers.SerializerMethodField()

    class Meta:
        model = FirewallSysEvent
        fields = '__all__'
        extra_fields = ('dev_name',)

    def get_dev_name(self, obj):
        return obj.device.name

    def to_internal_value(self, data):
        # turn status to is_read
        ret = super(FirewallSysEventSerializer, self).to_internal_value(data)
        if ret.get('status') == 1:
            ret['is_read'] = True
        return ret


class FirewallSysEventListUploadSerializer(serializers.ListSerializer):

    def create(self, validated_data):
        sys_events = [FirewallSysEvent(**item) for item in validated_data]
        return FirewallSysEvent.objects.bulk_create(sys_events)


class FirewallSysEventUploadSerializer(serializers.ModelSerializer):
    """
    SystemAlert upload info serializer
    """

    timestamp = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', source='occurred_time')

    class Meta:
        model = FirewallSysEvent
        fields = ('type', 'timestamp', 'content', 'level', 'status')
        list_serializer_class = FirewallSysEventListUploadSerializer

    def to_internal_value(self, data):
        # turn status to is_read
        ret = super(FirewallSysEventUploadSerializer, self).to_internal_value(data)
        if ret.get('status') == 1:
            ret['is_read'] = True
        return ret


class FirewallSecEventListUploadSerializer(serializers.ListSerializer):

    def create(self, validated_data):
        sec_events = [FirewallSecEvent(**item) for item in validated_data]
        return FirewallSecEvent.objects.bulk_create(sec_events)


class FirewallSecEventUploadSerializer(serializers.ModelSerializer):
    """
    SecAlert upload info serializer
    """
    sourceIp = serializers.IPAddressField(source='src_ip', allow_blank=True, allow_null=True)
    destinationIp = serializers.IPAddressField(source='dst_ip', allow_blank=True, allow_null=True)
    appLayerProtocol = serializers.CharField(source='app_layer_protocol', allow_blank=True, allow_null=True)
    packetLength = serializers.IntegerField(source='packet_length')
    riskLevel = serializers.IntegerField(source='level')
    signatureMessage = serializers.CharField(source='signature_msg', allow_blank=True, allow_null=True)
    matchedKey = serializers.CharField(source='matched_key', allow_blank=True, allow_null=True)
    protocolDetail = serializers.CharField(source='protocol_detail', allow_blank=True, allow_null=True)
    alertType = serializers.IntegerField(source='alert_type')
    sourceMac = serializers.CharField(source='src_mac', allow_blank=True, allow_null=True)
    destinationMac = serializers.CharField(source='dst_mac', allow_blank=True, allow_null=True)
    timestamp = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', source='occurred_time')

    class Meta:
        model = FirewallSecEvent
        fields = ('sourceIp', 'destinationIp', 'action', 'protocol', 'appLayerProtocol', 'packetLength',
                  'riskLevel', 'signatureMessage', 'matchedKey', 'protocolDetail', 'status', 'timestamp',
                  'alertType','packet', 'sourceMac', 'destinationMac')
        list_serializer_class = FirewallSecEventListUploadSerializer

    def to_internal_value(self, data):
        # turn status to is_read
        ret = super(FirewallSecEventUploadSerializer, self).to_internal_value(data)
        if ret.get('status') == 1:
            ret['is_read'] = True
        return ret


class FirewallLogUploadSerializer(serializers.Serializer):
    """
    Firewall log upload info serializer
    """
    FirewallLog_events = FirewallSysEventUploadSerializer(many=True, required=False)
    FirewallLog_incidents = FirewallSecEventUploadSerializer(many=True, required=False)

    def create(self, validated_data):
        device_id = validated_data.pop('device_id')
        if 'FirewallLog_events' in validated_data:
            firewall_sys_events = [FirewallSysEvent(**item, device_id=device_id) for item in validated_data['FirewallLog_events']]
            FirewallSysEvent.objects.bulk_create(firewall_sys_events)

        if 'FirewallLog_incidents' in validated_data:
            firewalllog_incidents_from_firewall = validated_data['FirewallLog_incidents']

            r = []
            for i in firewalllog_incidents_from_firewall:
                i['level'] += 1
                r.append(i)

            firewall_sec_events = [FirewallSecEvent(**item, device_id=device_id) for item in r]
            FirewallSecEvent.objects.bulk_create(firewall_sec_events)

            dev_sec_alert = []
            for ori_item in r:
                ori_item['sec_desc'] = ori_item['signature_msg']
                dev_sec_alert.append(ori_item)

            firewall_dev_all_alert = [DeviceAllAlert(**item, device_id=device_id, type=DeviceAllAlert.FIREWALL_EVENT, category=DeviceAllAlert.EVENT_FIREWALL) \
                                      for item in dev_sec_alert]
            DeviceAllAlert.objects.bulk_create(firewall_dev_all_alert)

        return validated_data
