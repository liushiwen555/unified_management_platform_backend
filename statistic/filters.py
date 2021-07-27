from django_filters import rest_framework as filters

from base_app.models import Device
from utils.core.filters import BaseFilters


class DeviceFilter(BaseFilters):
    name = filters.CharFilter(field_name='name', lookup_expr='exact')
    ip = filters.CharFilter(field_name='ip', lookup_expr='exact')

    class Meta:
        model = Device
        fields = ('name', 'ip')