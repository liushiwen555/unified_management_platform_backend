from django_filters import rest_framework as filters

from snmp.models import SNMPRule, SNMPTemplate, SNMPData
from utils.core.filters import BaseFilters


class SNMPRuleFilter(BaseFilters):
    name = filters.CharFilter(field_name='name', lookup_expr='contains')
    brand = filters.CharFilter(field_name='brand', lookup_expr='contains')
    hardware = filters.CharFilter(field_name='hardware', lookup_expr='contains')
    category = filters.NumberFilter(field_name='category', help_text='系统类别')
    type = filters.NumberFilter(field_name='type', help_text='系统类型')
    add = filters.NumberFilter(field_name='add', help_text='添加方式')

    class Meta:
        model = SNMPRule
        fields = ('category', 'type', 'add')


class SNMPTemplateFilter(BaseFilters):
    name = filters.CharFilter(field_name='name', lookup_expr='contains')
    brand = filters.CharFilter(field_name='brand', lookup_expr='contains')
    hardware = filters.CharFilter(field_name='hardware', lookup_expr='contains')
    category = filters.NumberFilter(field_name='category', help_text='资产类别')
    type = filters.NumberFilter(field_name='type', help_text='资产类型')
    add = filters.NumberFilter(field_name='add', help_text='添加方式')

    class Meta:
        model = SNMPTemplate
        fields = ('category', 'type', 'add')


class SNMPDataFilter(BaseFilters):
    name = filters.CharFilter(field_name='device__name', lookup_expr='exact',
                              help_text='资产名称')
    ip = filters.CharFilter(field_name='device__ip', lookup_expr='exact',
                            help_text='资产IP')

    class Meta:
        model = SNMPData
        fields = ('name', 'ip')
