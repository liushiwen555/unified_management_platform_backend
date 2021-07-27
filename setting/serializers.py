import ipaddress
from typing import Dict

from rest_framework import serializers

from setting.models import Setting, Location
from utils.core.exceptions import CustomError
from utils.ip_search import CitySearch


class IPInfoSerializer(serializers.Serializer):
    address = serializers.IPAddressField()
    net_mask = serializers.IPAddressField()
    gateway = serializers.IPAddressField()

    def validate(self, data):
        try:
            ipaddress.ip_interface('{}/{}'.format(data['address'], data['net_mask']))
        except ipaddress.NetmaskValueError:
            raise serializers.ValidationError('Netmask is invalid.')

        return data


class TimeInfoSerializer(serializers.Serializer):
    now = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S')


class NTPSettingSerializer(serializers.Serializer):
    ntp = serializers.CharField(help_text='NTP校时服务器')


class SettingSerializer(serializers.ModelSerializer):

    class Meta:
        model = Setting
        fields = ('lockout_threshold', 'lockout_duration',
                  'login_timeout_duration', 'change_psw_duration')

    def update(self, instance, validated_data):
        new_instance = super(SettingSerializer, self).update(instance, validated_data)
        # Reload middleware to take setting into effect.
        from unified_management_platform.wsgi import application
        application.load_middleware()
        return new_instance


class IPLimitSerializer(serializers.ModelSerializer):

    class Meta:
        model = Setting
        fields = ('ip_limit_enable', 'allowed_ip')

    def validate(self, attrs: Dict):
        if attrs['ip_limit_enable'] and not attrs['allowed_ip']:
            raise CustomError(error_code=CustomError.IP_TABLES_NULL_ERROR)
        return attrs

    def update(self, instance, validated_data):
        new_instance = super(IPLimitSerializer, self).update(instance, validated_data)
        # Reload middleware to take setting into effect.
        from unified_management_platform.wsgi import application
        application.load_middleware()
        return new_instance


class DiskSerializer(serializers.ModelSerializer):

    class Meta:
        model = Setting
        fields = ('disk_alert_percent', 'disk_clean_percent')


class SystemSecuritySerializer(serializers.ModelSerializer):
    class Meta:
        model = Setting
        fields = ('disk_alert_percent', 'disk_clean_percent',
                  'cpu_alert_percent', 'memory_alert_percent')


class SystemInfoSerializer(serializers.Serializer):
    model = serializers.CharField(label='设备型号')
    serial_no = serializers.CharField(label='序列号')
    version = serializers.CharField(label='软件版本')
    boot_time = serializers.CharField(label='上次开机时间')
    run_time = serializers.ListField(
        child=serializers.IntegerField(label='时/分/秒'),
        help_text='运行时长，[时，分，秒]')


class ThemeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Setting
        fields = ('theme', 'background')


class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ('country', 'province', 'city', 'latitude', 'longitude')
        extra_kwargs = {
            'country': {'required': False},
            'province': {'required': False},
            'latitude': {'required': False},
            'longitude': {'required': False},
        }

    def to_internal_value(self, data):
        city = data['city']
        if city[-1] == '市':
            city = city[:-1]
        info = CitySearch.search(city)
        if not info:
            raise CustomError(error_code=CustomError.CITY_NOT_FOUND)

        return {'country': info['country'], 'province': info['province'],
                'city': city, 'latitude': info['lat'],
                'longitude': info['long']}

    def save(self, **kwargs):
        location, _ = Location.objects.get_or_create(id=1)
        self.instance = location
        return super().save(**kwargs)


class SecurityCenterCleanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Setting
        fields = ('security_center',)
