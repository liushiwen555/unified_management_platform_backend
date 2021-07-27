from django_filters import rest_framework as filters

from utils.core.filters import BaseFilters
from base_app.models import Device


class DeviceFilter(BaseFilters):
    name = filters.CharFilter(field_name='name', lookup_expr='contains')
    ip = filters.CharFilter(field_name='ip', lookup_expr='contains')
    responsible_user = filters.CharFilter(field_name='responsible_user',
                                          lookup_expr='contains')
    location = filters.CharFilter(field_name='location', lookup_expr='contains')
    category = filters.NumberFilter(field_name='category', help_text='资产类别')
    type = filters.NumberFilter(field_name='type', help_text='资产类型')
    value = filters.NumberFilter(field_name='value', help_text='重要程度')
    ip_mac_bond = filters.BooleanFilter(field_name='ip_mac_bond',
                                        help_text='ipmac绑定状态')
    monitor = filters.BooleanFilter(field_name='monitor', help_text='监控状态')
    status = filters.BooleanFilter(field_name='status', help_text='在线状态')
    log_status = filters.BooleanFilter(field_name='log_status',
                                       help_text='日志监控状态')

    class Meta:
        model = Device
        fields = ('category', 'type', 'value', 'ip_mac_bond', 'monitor',
                  'status', 'log_status')


class CategoryDeviceFilter(BaseFilters):
    name = filters.CharFilter(field_name='name', lookup_expr='contains')
    ip = filters.CharFilter(field_name='ip', lookup_expr='contains')
    snmp_template = filters.CharFilter(
        field_name='snmpsetting__template__name', lookup_expr='contains')
    log_template = filters.CharFilter(field_name='log_template__name',
                                      lookup_expr='contains')

    class Meta:
        model = Device
        fields = ('name', 'ip', 'snmp_template', 'log_template', 'category',
                  'type', 'status', 'monitor', 'log_status')
