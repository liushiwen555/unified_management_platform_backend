from django_filters import rest_framework as filters

from firewall.models import FirewallSecEvent, FirewallSysEvent
from log.filters import BaseLogFilter


class FirewallSecEventFilter(BaseLogFilter):

    class Meta:
        model = FirewallSecEvent
        fields = ('id', 'level', 'protocol', 'src_ip', 'dst_ip', 'action', 'start_time', 'end_time',)


class FirewallSysEventFilter(BaseLogFilter):
    content = filters.CharFilter(field_name='content', lookup_expr='icontains')
    dev_name = filters.CharFilter(field_name='device__name',
                                  lookup_expr='contains', help_text='资产名称')

    class Meta:
        model = FirewallSysEvent
        fields = ('dev_name', 'level', 'type', 'start_time', 'end_time',)
