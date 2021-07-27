from typing import Dict, List, Optional

from drf_yasg import openapi
from rest_framework import serializers

from snmp.models import SNMPRule, SNMPTemplate, SNMPData, SNMPSetting
from utils.core.exceptions import CustomError
from statistic.serializers import UpdateTimeSerializer
from snmp.snmp_run import NetworkUsageClient
from utils.helper import safe_divide


class SNMPRuleSerializer(serializers.ModelSerializer):
    add = serializers.IntegerField(help_text='添加方式，只读', read_only=True)

    class Meta:
        model = SNMPRule
        fields = ('id', 'name', 'oid', 'field', 'category', 'type', 'brand',
                  'hardware', 'add', 'update_time', 'description')

    def create(self, validated_data: Dict):
        validated_data['add'] = SNMPRule.MANUAL_ADD
        return super().create(validated_data)


class SNMPTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SNMPTemplate
        fields = ('name', 'rules', 'category', 'type', 'brand', 'hardware',
                  'description')

    def to_internal_value(self, data: Dict):
        self._validate(data)
        return super(SNMPTemplateSerializer, self).to_internal_value(data)

    def create(self, validated_data):
        validated_data['add'] = SNMPTemplate.MANUAL_ADD
        return super().create(validated_data)

    def _validate(self, attrs: Dict) -> Dict:
        """
        由于name，category，type不重复的校验会早于validate，所有会提前报错
        这里声明方法放在 to_internal_value里调用
        """
        if self.instance:
            # 修改操作时，需要排除自己
            duplicated = SNMPTemplate.objects.filter(
                name=attrs['name'], category=attrs['category'],
                type=attrs['type']
            ).exclude(id=self.instance.id).exists()
        else:
            duplicated = SNMPTemplate.objects.filter(
                name=attrs['name'], category=attrs['category'],
                type=attrs['type']
            )

        if duplicated:
            raise CustomError(
                error_code=CustomError.REPEATED_NAME_CATEGORY_TYPE_ERROR)
        return attrs


class SimpleRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = SNMPRule
        fields = ('id', 'name', 'oid', 'field')


class SNMPTemplateListSerializer(serializers.ModelSerializer):
    device_count = serializers.SerializerMethodField(help_text='启用资产数')

    class Meta:
        model = SNMPTemplate
        fields = ('id', 'name', 'category', 'type', 'brand',
                  'hardware', 'add', 'update_time', 'description',
                  'device_count')

    def get_device_count(self, instance: SNMPTemplate) -> int:
        return instance.snmpsetting_set.count()


class SNMPTemplateRetrieveSerializer(serializers.ModelSerializer):
    rules = SimpleRuleSerializer(many=True, read_only=True)

    class Meta:
        model = SNMPTemplate
        fields = ('id', 'name', 'rules', 'category', 'type', 'brand',
                  'hardware', 'add', 'update_time', 'description')


class SNMPSettingSerializer(serializers.ModelSerializer):
    version = serializers.ChoiceField(
        choices=SNMPSetting.SNMP_VERSIONS,
        help_text=str(SNMPSetting.SNMP_VERSIONS),
    )
    security_level = serializers.ChoiceField(
        choices=SNMPSetting.SECURITY_LEVELS,
        help_text=str(SNMPSetting.SECURITY_LEVELS),
        required=False, allow_null=True, allow_blank=True
    )
    auth = serializers.ChoiceField(
        choices=SNMPSetting.AUTH_PROTOCOLS,
        help_text=str(SNMPSetting.AUTH_PROTOCOLS),
        required=False, allow_null=True, allow_blank=True,
    )
    priv = serializers.ChoiceField(
        choices=SNMPSetting.PRIV_PROTOCOLS,
        help_text=str(SNMPSetting.PRIV_PROTOCOLS),
        required=False, allow_null=True, allow_blank=True,
    )
    status = serializers.BooleanField(
        label='性能监控状态', source='device.monitor')
    community = serializers.CharField(
        label='读团体字', min_length=1, max_length=32)
    username = serializers.CharField(
        label='安全名', min_length=1, max_length=32, required=False,
        allow_null=True, allow_blank=True)
    auth_password = serializers.CharField(
        label='认证密码', min_length=8, max_length=32, required=False,
        allow_null=True, allow_blank=True)
    priv_password = serializers.CharField(
        label='加密密码', min_length=8, max_length=32, required=False,
        allow_null=True, allow_blank=True)

    class Meta:
        model = SNMPSetting
        fields = ('id', 'status', 'port', 'version',
                  'community', 'username', 'security_level', 'template',
                  'auth', 'auth_password', 'priv', 'priv_password')

    def update(self, instance: SNMPSetting, validated_data):
        device = validated_data.pop('device')
        self.instance = super().update(instance, validated_data)
        self.instance.device.monitor = device['monitor']
        self.instance.device.save(update_fields=['monitor'])
        return self.instance


class PartitionJSONField(serializers.JSONField):
    class Meta:
        swagger_schema_fields = openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'name': openapi.Schema('分区名', type=openapi.TYPE_STRING),
                    'used': openapi.Schema('已用空间', type=openapi.TYPE_NUMBER),
                    'total': openapi.Schema('总空间', type=openapi.TYPE_NUMBER),
                    'percent': openapi.Schema('百分比', type=openapi.TYPE_NUMBER),
                }
            )
        )


class DiskJSONField(serializers.SerializerMethodField):
    def to_internal_value(self, data):
        return data

    class Meta:
        swagger_schema_fields = openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'name': openapi.Schema('磁盘名', type=openapi.TYPE_STRING),
                    'read': openapi.Schema('读速度', type=openapi.TYPE_NUMBER),
                    'write': openapi.Schema('写速度', type=openapi.TYPE_NUMBER),
                }
            )
        )


class NetworkJSONField(serializers.JSONField):
    class Meta:
        swagger_schema_fields = openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'name': openapi.Schema('网卡名称', type=openapi.TYPE_STRING),
                    'in': openapi.Schema('流入速度', type=openapi.TYPE_NUMBER),
                    'out': openapi.Schema('流出速度', type=openapi.TYPE_NUMBER),
                }
            )
        )


class SNMPDataSerializer(serializers.ModelSerializer):
    ip = serializers.IPAddressField(source='device.ip', label='资产IP')
    name = serializers.CharField(source='device.name', label='资产名称')
    operation = serializers.CharField(label='操作系统')
    version = serializers.CharField(label='系统版本')
    system_runtime = serializers.ListField(help_text='系统运行时间, 天、时、分、秒')
    disk_speed = DiskJSONField(label='磁盘读写')
    process_count = serializers.SerializerMethodField()
    disk_usage = serializers.SerializerMethodField()
    network_speed = serializers.SerializerMethodField()
    # network_info = serializers.SerializerMethodField()
    network_usage = serializers.SerializerMethodField()
    update_time = UpdateTimeSerializer(help_text='统计时间')

    class Meta:
        model = SNMPData
        fields = ('ip', 'name', 'operation', 'version', 'system_runtime',
                  'cpu_in_use', 'cpu_cores',
                  'disk_in_use', 'disk_total', 'disk_used',
                  'memory_in_use', 'total_memory', 'memory_used',
                  'swap_memory_in_use', 'total_swap_memory', 'swap_memory_used',
                  'process_count', 'partition_usage', 'disk_speed', 'disk_usage',
                  'network_speed', 'network_usage',
                  'update_time')

    def to_representation(self, instance: SNMPData):
        self.snmp_data = SNMPData.objects.filter(
            id__lte=instance.id, device_id=instance.device_id)[:10]
        self.snmp_data = self.snmp_data[::-1]
        self.length = len(self.snmp_data)

        if not instance.system_info:
            instance.operation = None
            instance.version = None
        elif 'Windows' in instance.system_info:
            self.windows_system_info(instance.system_info, instance)
        else:
            self.linux_system_info(instance.system_info, instance)

        if instance.system_runtime:
            instance.system_runtime = instance.system_runtime.split(',')
        return super().to_representation(instance)

    def linux_system_info(self, system_info, instance):
        system_info = instance.system_info.split(' ')
        try:
            instance.operation = system_info[0]
            instance.version = system_info[2]
        except IndexError:
            instance.operation = system_info
            instance.version = None

    def windows_system_info(self, system_info, instance):
        instance.operation = 'Windows'
        instance.version = system_info.split('Windows')[-1]

    def is_none_data(self, field: str) -> bool:
        """
        判断snmp是否能正常采集这个数据
        :param field: 需要判断的字段
        :return: bool
        """
        for d in self.snmp_data:
            if getattr(d, field) is not None:
                return False
        return True

    def get_disk_speed(self, instance: SNMPData) -> Optional[Dict[str, Dict[str, List]]]:
        """
        :param instance:
        :return:
        {
           write: [],
           read: [],
        }
        """
        if self.is_none_data('disk_info'):
            return None

        disk_info = {
            'write': {'data': [0 for _ in range(self.length)]},
            'read': {'data': [0 for _ in range(self.length)]},
        }

        for i, data in enumerate(self.snmp_data):
            if not data.disk_info:
                continue
            write = 0
            read = 0
            for disk in data.disk_info:
                write -= disk['write']
                read += disk['read']
            disk_info['write']['data'][i] = round(write, 2)
            disk_info['read']['data'][i] = round(read, 2)

        return disk_info

    def get_process_count(self, instance: SNMPData) -> Optional[Dict[str, List]]:
        """

        :param instance:
        :return: {'data': []}
        """
        if self.is_none_data('process_count'):
            return None
        result = {'data': [0 for _ in range(len(self.snmp_data))]}
        for i in range(len(self.snmp_data)):
            result['data'][i] = self.snmp_data[i].process_count or 0
        return result

    def get_disk_usage(self, instance: SNMPData) -> Optional[Dict[str, Dict]]:
        """
        :param instance:
        :return:
        {
          write: {
            max: '', avg: '', current: '',
          },
          read: {
            max: '', avg: '', current: '',
          }
        }
        """
        if self.is_none_data('disk_info'):
            return None
        result = {
            'write': {'max': 0, 'avg': 0.0, 'current': 0},
            'read': {'max': 0, 'avg': 0.0, 'current': 0},
        }
        for data in self.snmp_data:
            if not data.disk_info:
                continue
            write = 0
            read = 0
            for disk in data.disk_info:
                write += disk['write']
                read += disk['read']
            result['write']['max'] = max(result['write']['max'], write)
            result['read']['max'] = max(result['read']['max'], read)
            result['write']['avg'] += write
            result['read']['avg'] += read
            result['write']['current'] = write
            result['read']['current'] = read

        result['write']['avg'] = safe_divide(result['write']['avg'], self.length, 2)
        result['read']['avg'] = safe_divide(result['read']['avg'], self.length, 2)
        for k, v in result['write'].items():
            result['write'][k] = round(v, 2)
        for k, v in result['read'].items():
            result['read'][k] = round(v, 2)
        return result

    def get_network_speed(self, instance: SNMPData):
        """
        :param instance:
        :return:
        {
          'in': {'data': []},
          'out': {'data': []},
        }
        """
        is_none = self.is_none_data('network_in_speed') or\
                  self.is_none_data('network_out_speed')
        if is_none:
            return None

        result = {
            'in': {'data': [0 for _ in range(self.length)]},
            'out': {'data': [0 for _ in range(self.length)]},
        }
        for i, data in enumerate(self.snmp_data):
            result['in']['data'][i] = -round(data.network_in_speed or 0, 2)
            result['out']['data'][i] = round(data.network_out_speed or 0, 2)
        return result

    def get_network_usage(self, instance: SNMPData) -> Optional[Dict[str, Dict]]:
        """
        :param instance:
        :return:
        {
          in: {
            max: '', avg: '', current: '',
          },
          out: {
            max: '', avg: '', current: '',
          }
        }
        """
        if self.is_none_data('network_usage'):
            return None
        result = {
            'in': {'max': 0, 'avg': 0.0, 'current': 0},
            'out': {'max': 0, 'avg': 0.0, 'current': 0},
        }
        for data in self.snmp_data:
            if not data.network_usage:
                continue
            in_ = 0
            out = 0
            for interface in data.network_usage:
                if not NetworkUsageClient.is_physical_interface(interface['name']):
                    continue
                in_ += interface['in']
                out += interface['out']
            result['in']['max'] = max(result['in']['max'], in_)
            result['out']['max'] = max(result['out']['max'], out)
            result['in']['current'] = in_
            result['out']['current'] = out
            result['in']['avg'] += in_
            result['out']['avg'] += out

        result['in']['avg'] = round(result['in']['avg'] / self.length, 2)
        result['out']['avg'] = round(result['out']['avg'] / self.length, 2)
        for k, v in result['in'].items():
            result['in'][k] = round(v, 2)
        for k, v in result['out'].items():
            result['out'][k] = round(v, 2)
        return result

    def get_update_time(self, instance: SNMPData):
        return [d.update_time for d in self.snmp_data]
