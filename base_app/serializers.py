from datetime import datetime

from django.utils import timezone
from rest_framework import serializers

from auditor.models import AuditSecAlert
from auditor.serializers import AuditSecAlertNoticeSerializer, \
    AuditSysAlertNoticeSerializer
from base_app.models import Device, StrategyTemplate, TerminalLog, \
    DeviceMonitorSetting, EventLog
from firewall.models import FirewallSecEvent
from firewall.serializers import FirewallSecEventNoticeSerializer
from unified_log.elastic.elastic_model import BaseDocument
from unified_log.models import LogProcessTemplate
from unified_log.models import LogStatistic
from snmp.models import SNMPData


class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('name', 'brand', 'hardware', 'category', 'type', 'ip',
                  'value', 'mac', 'ip_mac_bond', 'responsible_user', 'monitor',
                  'location', 'description', 'log_template', 'log_status',
                  'version')


class AuditorFirewallDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('id', 'name', 'ip', 'status', 'responsible_user', 'location',
                  'template_name', 'strategy_apply_status', 'registered_time')


class DeviceUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('name', 'brand', 'hardware', 'category', 'ip', 'type', 'mac',
                  'value', 'ip_mac_bond', 'responsible_user', 'monitor',
                  'location', 'description', 'log_status', 'version')


class DeviceAllUpdateSerializer(serializers.Serializer):
    ip_mac_bond = serializers.BooleanField(
        required=False, help_text='IPMAC绑定')
    responsible_user = serializers.CharField(required=False, help_text='负责任')
    location = serializers.CharField(required=False, help_text='位置')
    monitor = serializers.BooleanField(required=False, help_text='监控状态')
    log_status = serializers.BooleanField(required=False,
                                              help_text='日志监控开关')
    value = serializers.CharField(required=False, help_text='重要程度')


class DeviceBulkUpdateSerializer(DeviceAllUpdateSerializer):
    ids = serializers.ListField(child=serializers.IntegerField(),
                                allow_empty=False, help_text='资产的 id 列表')


class LogStatisticSerializer(serializers.ModelSerializer):
    today = serializers.IntegerField(read_only=True)
    total = serializers.IntegerField(read_only=True)
    update_time = serializers.DateTimeField(read_only=True)

    class Meta:
        model = LogStatistic
        fields = ('today', 'total', 'update_time')


class DeviceRetrieveSerializer(serializers.ModelSerializer):
    log_template = serializers.CharField(
        read_only=True, source='log_template.name', help_text='日志解析模板')
    cpu_in_use = serializers.IntegerField(help_text='CPU使用率', default=0)
    memory_in_use = serializers.IntegerField(help_text='内存使用率', default=0)
    disk_in_use = serializers.IntegerField(help_text='磁盘使用率', default=0)
    network_in_speed = serializers.IntegerField(help_text='网络in速度', default=0)
    network_out_speed = serializers.IntegerField(help_text='网络out速度', default=0)
    snmp_update_time = serializers.DateTimeField(help_text='性能上次采集时间',
                                                 default=None)
    today_log = serializers.IntegerField(
        source='logstatistic.today', default=0, help_text='今日日志')
    total_log = serializers.IntegerField(
        source='logstatistic.total', default=0, help_text='累计日志')
    log_update_time = serializers.DateTimeField(
        source='logstatistic.update_time', help_text='日志上次采集时间')

    class Meta:
        model = Device
        fields = (
        'id', 'name', 'brand', 'hardware', 'category', 'ip', 'type', 'mac',
        'ip_mac_bond', 'responsible_user', 'monitor', 'location', 'description',
        'value', 'created_at', 'status', 'cpu_in_use', 'memory_in_use',
        'disk_in_use', 'network_in_speed', 'network_out_speed',
        'last_online_time',
        'registered_time', 'apply_time', 'register_code', 'template_name',
        'strategy_apply_status', 'log_template', 'log_status', 'today_log',
        'total_log', 'log_update_time', 'snmp_update_time', 'version')

    def to_representation(self, instance: Device):
        snmp_data: SNMPData = instance.snmpdata_set.order_by('-id').first()
        if not snmp_data:
            return super().to_representation(instance)
        instance.cpu_in_use = snmp_data.cpu_in_use
        instance.memory_in_use = snmp_data.memory_in_use
        instance.disk_in_use = snmp_data.disk_in_use
        instance.network_in_speed = snmp_data.network_in_speed
        instance.network_out_speed = snmp_data.network_out_speed
        instance.snmp_update_time = snmp_data.update_time
        return super().to_representation(instance)


class DeviceListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('id', 'name', 'category', 'type', 'ip', 'ip_mac_bond',
                  'monitor', 'log_status', 'responsible_user', 'location')


class DeviceCategorySerializer(serializers.ModelSerializer):
    snmp_template = serializers.CharField(
        label='性能监控模板名称', source='snmpsetting.template.name',
        required=False, default='')
    log_template = serializers.SlugRelatedField(
        slug_field='name', queryset=LogProcessTemplate.objects.all(),
        label='日志监控模板名称', required=False,
    )
    total_log = serializers.CharField(
        label='累计日志数', source='logstatistic.total', required=False,
        default=0,
    )

    class Meta:
        model = Device
        fields = ('id', 'name', 'category', 'type', 'ip', 'status', 'monitor',
                  'log_status', 'snmp_template', 'log_template', 'total_log')


class DeviceImportSerializer(serializers.Serializer):
    file = serializers.FileField(required=True, help_text='批量导入资产表格，xlsx 类型')


class DeviceExportSerializer(serializers.Serializer):
    id = serializers.ListField(
        child=serializers.IntegerField(), allow_empty=False,
        help_text='导出的资产id 列表, 列表形式[1,2,3]')


class DeviceExportDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('id', 'name', 'category', 'type', 'brand', 'hardware',
                  'value', 'ip', 'mac', 'responsible_user', 'location',
                  'description', 'created_at', 'version')

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data.update(type=instance.get_type_display())
        data.update(value=instance.get_value_display())
        return data


class DeviceMonitorSettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceMonitorSetting
        fields = '__all__'


class DeviceMonitorFrequencySerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceMonitorSetting
        fields = ('security_monitor_period', 'communication_monitor_period',
                  'server_monitor_period', 'control_monitor_period')


class DeviceMonitorTresholdSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceMonitorSetting
        exclude = (
        'id', 'security_monitor_period', 'communication_monitor_period',
        'server_monitor_period', 'control_monitor_period')


class BatchOperationSerializer(serializers.Serializer):
    REBOOT = 1
    UN_REGISTER = 2

    dev_ids = serializers.ListField(child=serializers.IntegerField(),
                                    allow_empty=False)
    password = serializers.CharField(required=False)
    operation = serializers.IntegerField()


class TemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = StrategyTemplate
        fields = ('id', 'name', 'created_time', 'apply_time')


class TemplateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = StrategyTemplate
        fields = ('name',)


class DeployTemp2DeviceSerializer(serializers.Serializer):
    dev_ids = serializers.ListField(child=serializers.IntegerField(),
                                    allow_empty=False)


class RegisterSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()
    register_code = serializers.CharField()
    version = serializers.CharField()


class UnRegisterSerializer(serializers.Serializer):
    ip = serializers.IPAddressField()


class TerminalLogSerializer(serializers.ModelSerializer):
    device = serializers.SlugRelatedField(read_only=True, slug_field='name')
    device_type = serializers.SlugRelatedField(read_only=True,
                                               slug_field='type',
                                               source='device')

    class Meta:
        model = TerminalLog
        fields = (
        'id', 'device', 'occurred_time', 'content', 'device_type', 'level')

    def to_representation(self, instance):
        if isinstance(instance, FirewallSecEvent):
            return FirewallSecEventNoticeSerializer(instance=instance).data
        elif isinstance(instance, AuditSecAlert):
            return AuditSecAlertNoticeSerializer(instance=instance).data
        else:
            return AuditSysAlertNoticeSerializer(instance=instance).data


class EventLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = EventLog
        fields = ('id', 'name', 'category', 'type', 'level', 'desc')


class DeviceFilterSerializer(serializers.ModelSerializer):
    category = serializers.ChoiceField(choices=Device.CATEGORY_CHOICE,
                                       help_text='资产类别', required=False)
    type = serializers.ChoiceField(choices=Device.DEV_TEMP_TYPE_CHOICES,
                                   help_text='资产类型', required=False)
    ip = serializers.IPAddressField(help_text='IP', required=False)
    name = serializers.CharField(help_text='资产名称', required=False)
    ip_mac_bond = serializers.NullBooleanField(help_text='IPMAC绑定状态',
                                               required=False)
    monitor = serializers.NullBooleanField(help_text='监控状态', required=False)
    log_status = serializers.NullBooleanField(help_text='日志监控状态',
                                              required=False)

    class Meta:
        model = Device
        fields = ('category', 'value', 'ip_mac_bond', 'monitor', 'type',
                  'status', 'log_status', 'name', 'ip', 'responsible_user',
                  'location')


class ExportDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('category', 'value', 'ip_mac_bond', 'monitor', 'type',
                  'status', 'log_status', 'name', 'ip', 'responsible_user',
                  'location')


class LogSettingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('log_status', 'log_template')


class ImportDeviceSerializer(serializers.ModelSerializer):
    error = serializers.CharField(label='资产解析结果', allow_blank=True,
                                  help_text='解析正常时字段为空', allow_null=True)
    valid = serializers.BooleanField(label='资产解析成功状态')

    class Meta:
        model = Device
        fields = ('id', 'name', 'category', 'type', 'brand', 'hardware', 'ip',
                  'mac', 'responsible_user', 'location', 'value', 'description',
                  'version', 'error', 'valid')
        extra_kwargs = {
            'name': {'error_messages': {
                'max_length': '资产名称超过最大长度{max_length}'}
            }
        }

    def create(self, validated_data):
        validated_data.pop('error')
        validated_data.pop('valid')

        return super().create(validated_data)

    def to_representation(self, instance: Device):
        if not hasattr(instance, 'error'):
            instance.error = ''
        if not hasattr(instance, 'valid'):
            instance.valid = True
        return super().to_representation(instance)


class ImportDeviceBody(serializers.Serializer):
    file = serializers.FileField(label='导入资产文件, excel文件')


class ACKImportDeviceSerializer(serializers.Serializer):
    """
    确认导入资产的请求体
    """
    data = ImportDeviceSerializer(many=True)
