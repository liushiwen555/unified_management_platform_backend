from rest_framework import serializers

from log.models import ServerRunLog, TerminalInstallationLog, TerminalRunLog, StrategyDistributionStatusLog, \
    DeviceAllAlert, UnifiedForumLog, ReportLog, SecurityEvent


def _render_blacklist_sec_alert(sec_alert: DeviceAllAlert) -> str:
    sid = sec_alert.other_info.get('sid')
    content = f'流量 {sec_alert.src_ip}:{sec_alert.src_port} -> {sec_alert.dst_ip}:{sec_alert.dst_port} ' \
              f'符合已有威胁特征{sid}'
    return content


def _render_illegal_ip_sec_alert(sec_alert: DeviceAllAlert) -> str:
    return f'陌生IP {",".join(sec_alert.illegal_ip)}未在资产列表中添加'


def _render_illegal_flow_sec_alert(sec_alert: DeviceAllAlert) -> str:
    return f'流量 {sec_alert.src_ip}:{sec_alert.src_port}, {sec_alert.dst_ip}:{sec_alert.dst_port}未在白名单策略中记录'


def _render_mac_not_match_sec_alert(sec_alert: DeviceAllAlert) -> str:
    ip = sec_alert.src_ip if sec_alert.conflict_mac == sec_alert.src_mac else sec_alert.dst_ip
    return f'流量 IP {ip}, MAC {sec_alert.conflict_mac}'


def _render_ics_sec_alert(sec_alert: DeviceAllAlert) -> str:
    return f'流量{sec_alert.src_ip}:{sec_alert.src_port}，{sec_alert.dst_ip}:{sec_alert.dst_port} ' \
           f'{sec_alert.protocol} 的功能码未在白名单策略中记录'


def update_ret_with_sec_desc(ret, alert:DeviceAllAlert):
    alert_type = alert.type
    content = alert.sec_desc
    if alert_type == DeviceAllAlert.AUDITOR_EVENT_BLACKLIST:
        content = _render_blacklist_sec_alert(alert)

    if alert_type == DeviceAllAlert.AUDITOR_EVENT_ILLEGAL_IP:
        content = _render_illegal_ip_sec_alert(alert)

    if alert_type == DeviceAllAlert.AUDITOR_EVENT_ILLEGAL_FLOW:
        content = _render_illegal_flow_sec_alert(alert)

    if alert_type == DeviceAllAlert.AUDITOR_EVENT_MAC_NOT_MATCH:
        content = _render_mac_not_match_sec_alert(alert)

    if alert_type == DeviceAllAlert.AUDITOR_EVENT_ICS:
        content = _render_ics_sec_alert(alert)

    ret['sec_desc'] = content

    return ret


class ServerRunLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = ServerRunLog
        fields = ('id', 'type', 'content', 'occurred_time')


class TerminalDevInstallationLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = TerminalInstallationLog
        fields = ('id', 'dev_name', 'result', 'content', 'dev_type', 'occurred_time')


class TerminalDevRunLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = TerminalRunLog
        fields = ('id', 'dev_name', 'dev_type', 'action', 'occurred_time')


class StrategyDistributionStatusLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = StrategyDistributionStatusLog
        fields = ('id', 'dev_name', 'dev_type', 'content', 'distribute_time', 'distribute_status',
                  'handle_time', 'dev_handle_status', 'occurred_time', 'is_read', 'read_at')


class DeviceAllAlertSerializer(serializers.ModelSerializer):

    device_id = serializers.SlugRelatedField(read_only=True, slug_field='id', source='device')
    device_name = serializers.SlugRelatedField(read_only=True, slug_field='name', source='device')

    class Meta:
        model = DeviceAllAlert
        fields = ('id', 'occurred_time', 'level', 'category', 'type',
                  'sec_desc', 'status_resolved', 'device_id', 'device_name',
                  'protocol')


class DeviceAllAlertDetailSerializer(serializers.ModelSerializer):
    device_id = serializers.SlugRelatedField(read_only=True, slug_field='id', source='device')
    event_log_id = serializers.SlugRelatedField(read_only=True, slug_field='id', source='event_log')
    user_name = serializers.SlugRelatedField(read_only=True, slug_field='username', source='user')
    device_name = serializers.SlugRelatedField(read_only=True, slug_field='name', source='device')

    class Meta:
        model = DeviceAllAlert
        fields = ('id', 'occurred_time', 'level', 'category', 'type', 'sec_desc', 'status_resolved',
                  'event_log_id',  'des_resolved', 'time_resolved', 'user_name', 'device_name',
                  'device_id', 'protocol', 'suggest_desc')


class AuditSecAlertToDeviceUploadListSerializer(serializers.ListSerializer):

    def create(self, validated_data):
        sec_alerts = [DeviceAllAlert(**item) for item in validated_data]
        return DeviceAllAlert.objects.bulk_create(sec_alerts)


class AuditSecAlertToDeviceAllAlertSerializer(serializers.ModelSerializer):

    class Meta:
        model = DeviceAllAlert
        fields = '__all__'
        extra_fields = ('user',)


class DeviceAlertHomeSerializer(serializers.ModelSerializer):

    class Meta:
        model = DeviceAllAlert
        fields = ('id', 'occurred_time', 'sec_desc')


class ResolveDeviceAlertSerializer(serializers.Serializer):
    des_resolved = serializers.CharField(
        required=False, allow_null=True, allow_blank=True, label='备注')
    status_resolved = serializers.ChoiceField(
        DeviceAllAlert.RESOLVED_STATUS_CHOICES, required=True, label='处理状态',
        help_text=str(DeviceAllAlert.RESOLVED_STATUS_CHOICES)
    )


class BatchDeviceAlertSerialzier(ResolveDeviceAlertSerializer):
    ids = serializers.ListField(
        child=serializers.IntegerField(), required=False, allow_null=True,
        allow_empty=True, label='告警id列表')


class DeviceAlertResolveSerialzier(serializers.Serializer):
    des_resolved = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    status_resolved = serializers.IntegerField(required=True)


class UnifiedForumLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = UnifiedForumLog
        fields = ('id', 'type', 'category',  'occurred_time', 'content', 'user',
                  'ip', 'group')


class ReportLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = ReportLog
        fields = ('id', 'occurred_time', 'start_time', 'end_time')


class ReportLogDetailSerializer(serializers.ModelSerializer):

    class Meta:
        model = ReportLog
        exclude = ['id',]


class ReportGenerateSerializer(serializers.ModelSerializer):

    class Meta:
        model = ReportLog
        fields = ('start_time', 'end_time')


class DeviceAlertFilterSerializer(serializers.Serializer):
    sec_desc = serializers.CharField(label='告警描述', required=False)
    level = serializers.ChoiceField(
        DeviceAllAlert.LEVEL_CHOICE, label='告警等级', allow_null=True,
        help_text=str(DeviceAllAlert.LEVEL_CHOICE), allow_blank=True,
        required=False
    )
    type = serializers.ChoiceField(
        DeviceAllAlert.TYPE_CHOICES, label='告警类型', allow_blank=True,
        help_text=str(DeviceAllAlert.TYPE_CHOICES), allow_null=True,
        required=False
    )
    status_resolved = serializers.ChoiceField(
        DeviceAllAlert.RESOLVED_STATUS_CHOICES, label='处理状态',
        help_text=str(DeviceAllAlert.RESOLVED_STATUS_CHOICES), allow_null=True,
        allow_blank=True, required=False
    )
    category = serializers.ChoiceField(
        DeviceAllAlert.EVENT_CATEGORY_CHOICE, label='告警类别', allow_null=True,
        help_text=str(DeviceAllAlert.EVENT_CATEGORY_CHOICE), allow_blank=True,
        required=False
    )
    protocol = serializers.CharField(label='协议', required=False)
    start_time = serializers.DateTimeField(required=False)
    end_time = serializers.DateTimeField(required=False)


class SecurityEventFilterSerializer(serializers.Serializer):
    content = serializers.CharField(label='事件描述', required=False)
    level = serializers.ChoiceField(
        SecurityEvent.LEVEL_CHOICE, label='事件等级', allow_null=True,
        help_text=str(SecurityEvent.LEVEL_CHOICE), allow_blank=True,
        required=False
    )
    type = serializers.ChoiceField(
        SecurityEvent.TYPE_CHOICES, label='事件类型', allow_blank=True,
        help_text=str(SecurityEvent.TYPE_CHOICES), allow_null=True,
        required=False
    )
    status_resolved = serializers.ChoiceField(
        SecurityEvent.RESOLVED_STATUS_CHOICES, label='处理状态',
        help_text=str(SecurityEvent.RESOLVED_STATUS_CHOICES), allow_null=True,
        allow_blank=True, required=False
    )
    category = serializers.ChoiceField(
        SecurityEvent.CATEGORY_CHOICES, label='事件类别', allow_null=True,
        help_text=str(SecurityEvent.CATEGORY_CHOICES), allow_blank=True,
        required=False
    )
    start_time = serializers.DateTimeField(required=False)
    end_time = serializers.DateTimeField(required=False)


class SecurityEventListSerializer(serializers.ModelSerializer):
    device_name = serializers.SlugRelatedField(
        read_only=True, slug_field='name', source='device')

    class Meta:
        model = SecurityEvent
        fields = ('id', 'device_name', 'level', 'category', 'type', 'content',
                  'occurred_time', 'status_resolved')
        extra_kwargs = {
            'category': {'help_text': str(SecurityEvent.CATEGORY_CHOICES)},
            'type': {'help_text': str(SecurityEvent.TYPE_CHOICES)},
        }


class SecurityEventDetailSerializer(serializers.ModelSerializer):
    device_id = serializers.SlugRelatedField(
        read_only=True, slug_field='id', source='device')
    device_name = serializers.SlugRelatedField(
        read_only=True, slug_field='name', source='device')
    username = serializers.SlugRelatedField(
        label='处理人账户', read_only=True, slug_field='username', source='user'
    )

    class Meta:
        model = SecurityEvent
        fields = ('id', 'device_name', 'level', 'category', 'type', 'content',
                  'occurred_time', 'status_resolved', 'device_id',
                  'status_resolved', 'des_resolved', 'time_resolved', 'username')
        extra_kwargs = {
            'category': {'help_text': str(SecurityEvent.CATEGORY_CHOICES)},
            'type': {'help_text': str(SecurityEvent.TYPE_CHOICES)},
        }


class StatisticInfoSerializer(serializers.ModelSerializer):
    all_count = serializers.IntegerField(label='告警总量')
    last_alert_time = serializers.DateTimeField(label='最近告警时间')
    unresolved_count = serializers.IntegerField(label='未处理告警数')

    class Meta:
        model = DeviceAllAlert
        fields = ('all_count', 'last_alert_time', 'unresolved_count')


class AuditorProtocolQuerySerializer(serializers.Serializer):
    start_time = serializers.DateTimeField(help_text='开始时间', required=False)
    end_time = serializers.DateTimeField(help_text='结束时间', required=False)
    ip = serializers.CharField(help_text='IP', required=False, allow_null=True,
                               allow_blank=True)
    mac = serializers.CharField(help_text='MAC地址', required=False, allow_null=True,
                                allow_blank=True)
    port = serializers.IntegerField(help_text='端口', required=False)
    l4_protocol = serializers.IntegerField(help_text='传输层协议', required=False)
    protocol = serializers.CharField(help_text='应用层协议', required=False,
                                     allow_null=True, allow_blank=True)
    page = serializers.IntegerField()
    page_size = serializers.IntegerField()


class AuditorProtocolSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    src_ip = serializers.CharField(label='源IP')
    src_mac = serializers.CharField(label='源MAC')
    src_port = serializers.IntegerField(label='源端口')
    dst_ip = serializers.CharField(label='目的IP')
    dst_mac = serializers.CharField(label='目的MAC')
    dst_port = serializers.IntegerField(label='目的端口')
    l4_protocol = serializers.IntegerField(label='传输层协议',
                                           help_text="((1, 'TCP'), (2, 'UDP'))")
    protocol = serializers.CharField(label='协议')
    content = serializers.CharField(label='应用层内容')
    occurred_at = serializers.DateTimeField()
