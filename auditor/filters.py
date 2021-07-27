from django_filters import rest_framework as filters

from auditor.models import AuditSecAlert, AuditSysAlert
from log.filters import BaseLogFilter
from utils.constants import PRO_PROFINET, PRO_PROFINET_DCP, PRO_PROFINET_PTCP, PRO_PROFINET_IRT, PRO_PROFINET_IO


class AuditSecAlertFilter(BaseLogFilter):
    protocol = filters.CharFilter(method='protocol_filter_method')

    class Meta:
        model = AuditSecAlert
        fields = ('id', 'is_read', 'level', 'category', 'protocol', 'src_ip',
                  'dst_ip', 'start_time', 'end_time',)

    def protocol_filter_method(self, queryset, name, value):
        if value == PRO_PROFINET:
            return queryset.filter(
                **{'{}__in'.format(name): [PRO_PROFINET_DCP, PRO_PROFINET_PTCP, PRO_PROFINET_IRT, PRO_PROFINET_IO]})
        else:
            return queryset.filter(**{
                name: value,
            })


class AuditSysAlertFilter(BaseLogFilter):
    class Meta:
        model = AuditSysAlert
        fields = ('id', 'is_read', 'level', 'category', 'start_time', 'end_time',)


class AuditLogFilter(BaseLogFilter):
    dev_name = filters.CharFilter(field_name='device__name',
                                  lookup_expr='contains', help_text='资产名称')
    ip = filters.CharFilter(field_name='ip', lookup_expr='contains')

    class Meta:
        model = AuditSysAlert
        fields = ('ip', 'is_read', 'category', 'start_time', 'end_time',)