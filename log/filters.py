from django_filters import rest_framework as filters

from utils.core.filters import BaseFilters
from log.models import DeviceAllAlert, UnifiedForumLog, ServerRunLog, \
    StrategyDistributionStatusLog, TerminalRunLog, TerminalInstallationLog,\
    SecurityEvent


class BaseLogFilter(filters.FilterSet):
    start_time = filters.IsoDateTimeFilter(field_name='occurred_time',
                                           lookup_expr='gte')
    end_time = filters.IsoDateTimeFilter(field_name='occurred_time',
                                         lookup_expr='lt')
    is_read = filters.BooleanFilter()


class UnifiedForumLogFilter(BaseLogFilter, BaseFilters):
    ip = filters.CharFilter(field_name='ip', lookup_expr='contains',
                            help_text='IP')
    user = filters.CharFilter(field_name='user', lookup_expr='contains',
                              help_text='用户名')

    class Meta:
        model = UnifiedForumLog
        fields = ('ip', 'type', 'category', 'user', 'group', 'start_time',
                  'end_time',)


class ServerRunLogFilter(BaseLogFilter):
    content = filters.CharFilter(field_name='content', lookup_expr='icontains')

    class Meta:
        model = ServerRunLog
        fields = ('id', 'type', 'content', 'start_time', 'end_time',)


class TerminalDevInstallationLogFilter(BaseLogFilter):
    content = filters.CharFilter(field_name='content', lookup_expr='icontains')

    class Meta:
        model = TerminalInstallationLog
        fields = ('id', 'dev_name', 'result', 'content', 'end_time',)


class TerminalDevRunLogFilter(BaseLogFilter):
    class Meta:
        model = TerminalRunLog
        fields = ('id', 'dev_name', 'action', 'start_time', 'end_time',)


class StrategyDistributionStatusLogFilter(BaseLogFilter):
    class Meta:
        model = StrategyDistributionStatusLog
        fields = ('id', 'dev_name', 'dev_type', 'start_time', 'end_time',)


class AllDeviceAlertFilter(BaseLogFilter):
    sec_desc = filters.CharFilter(field_name='sec_desc',
                                  lookup_expr='contains', help_text='描述')
    category = filters.NumberFilter(
        field_name='category', help_text=DeviceAllAlert.EVENT_CATEGORY_CHOICE,
        lookup_expr='exact'
    )
    type = filters.NumberFilter(
        field_name='type', help_text=DeviceAllAlert.TYPE_CHOICES,
        lookup_expr='exact'
    )

    class Meta:
        model = DeviceAllAlert
        fields = ('level', 'type', 'status_resolved', 'category', 'sec_desc',
                  'protocol')


class SecurityEventFilter(BaseLogFilter):
    content = filters.CharFilter(field_name='content',
                                 lookup_expr='contains', help_text='描述')

    class Meta:
        model = SecurityEvent
        fields = ('level', 'type', 'status_resolved', 'category', 'content')
