from django.conf import settings
from django.contrib.postgres.fields import ArrayField, JSONField
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import MinValueValidator, MaxValueValidator, \
    RegexValidator
from django.db import models
from django.utils import timezone

from base_app.models import EventLog
from base_app.models import Log, Device
from utils.validators import MAC_VALIDATOR
from user.models import User

MACAddrValidator = RegexValidator(regex=r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$',
                                  message='Enter a valid MAC address, for example "12:AD:34:EC:4D:1B".')


class UnifiedForumLog(Log):
    """
    合并原来的登录日志，授权日志，以及管理日志三个部分
    """

    # 日志类型——和功能模块对应：安全中心，告警管理，策略管理，资产管理，系统管理，授权管理
    # 登录，登出，CPU日志，存储日志, 知识库
    TYPE_SECURITY = 1
    TYPE_ALARM = 2
    TYPE_STRATEGY = 3
    TYPE_ASSETS = 4
    TYPE_SYSTEM = 5
    TYPE_AUTH = 6
    TYPE_LOGIN = 7
    TYPE_LOGOUT = 8
    TYPE_CPU = 9
    TYPE_STORAGE = 10
    TYPE_KNOWLEDGE = 11
    TYPE_MEMORY = 12
    TYPE_THEME = 13
    TYPE_AUTH_SECURITY = 14

    TYPE_CHOICE = (
        (TYPE_SECURITY, '安全中心'),
        (TYPE_ALARM, '告警管理'),
        (TYPE_STRATEGY, '策略管理'),
        (TYPE_ASSETS, '资产管理'),
        (TYPE_SYSTEM, '系统管理'),
        (TYPE_AUTH, '权限管理'),
        (TYPE_LOGIN, '登录'),
        (TYPE_LOGOUT, '登出'),
        (TYPE_CPU, 'CPU使用'),
        (TYPE_MEMORY, '内存使用'),
        (TYPE_STORAGE, '存储使用'),
        (TYPE_KNOWLEDGE, '知识管理'),
        (TYPE_THEME, '外观设置'),
        (TYPE_AUTH_SECURITY, '账号安全'),
    )

    # 日志类别：操作日志，用户管理，登录登出，系统日志
    CATEGORY_OPERATION = 1
    CATEGORY_USER_MANAGEMENT = 2
    CATEGORY_LOGIN_LOGOUT = 3
    CATEGORY_SYSTEM = 4
    # CATEGORY_THEME = 5

    CATEGORY_CHOICE = (
        (CATEGORY_LOGIN_LOGOUT, '登录登出'),
        (CATEGORY_OPERATION, '操作日志'),
        (CATEGORY_USER_MANAGEMENT, '用户管理'),
        (CATEGORY_SYSTEM, '系统日志'),
        # (CATEGORY_THEME, '外观设置'),
    )

    # 日志类别对的日志属性
    OPERATOR_TYPE = [
        TYPE_SECURITY,
        TYPE_ALARM,
        TYPE_STRATEGY,
        TYPE_ASSETS,
        TYPE_SYSTEM,
        TYPE_KNOWLEDGE,
        TYPE_THEME,
    ]

    USER_MANAGEMENT_TYPE = [TYPE_AUTH]

    LOGIN_LOGOUT_TYPE = [TYPE_LOGIN, TYPE_LOGOUT]

    SYSTEM_TYPE = [TYPE_CPU, TYPE_STORAGE, TYPE_MEMORY, TYPE_AUTH_SECURITY]

    category = models.IntegerField('日志类别', choices=CATEGORY_CHOICE,
                                   null=True, help_text=str(CATEGORY_CHOICE))
    user = models.CharField('用户名/操作人', max_length=20)
    group = models.CharField('操作角色', max_length=20)
    ip = models.GenericIPAddressField('IP地址', null=True)
    type = models.IntegerField('类型', choices=TYPE_CHOICE,
                               help_text=str(TYPE_CHOICE))
    result = models.BooleanField('结果', default=False)

    class Meta:
        verbose_name = '本机日志'
        ordering = ['-occurred_time', 'id']

    def __str__(self):
        return '{} {} {}'.format(self.id, self.user, self.get_type_display())

    @classmethod
    def reboot_log(cls, request, success=False):
        user = request.user
        group = user.group.name
        ip = request.META['REMOTE_ADDR']
        if success:
            content = '设备重启, 成功'
        else:
            content = '设备重启, 失败'
        cls.objects.create(
            user=user.username, group=group, ip=ip, content=content,
            category=cls.CATEGORY_OPERATION, type=cls.TYPE_SYSTEM,
        )


class ServerRunLog(Log):
    TYPE_CHOICE = (
        (1, '登录'),
        (2, '授权'),
        (3, '管理'),
    )

    type = models.IntegerField('类型', choices=TYPE_CHOICE)

    class Meta:
        verbose_name = '服务器运行日志'

    def __str__(self):
        return '{} {}'.format(self.id, self.content[0:20])


class TerminalInstallationLog(Log):
    dev_name = models.CharField('设备名称', max_length=20)
    dev_type = models.IntegerField('设备类型', choices=Device.DEV_TEMP_TYPE_CHOICES)
    result = models.BooleanField('结果', default=False)

    class Meta:
        verbose_name = '终端安装日志'

    def __str__(self):
        return '{} {}'.format(self.id, self.content[0:20])


class TerminalRunLog(Log):
    ACTION_ON = 1
    ACTION_OFF = 2
    ACTION_CHOICES = (
        (ACTION_ON, '上线'),
        (ACTION_OFF, '离线'),
    )

    dev_name = models.CharField('设备名称', max_length=20)
    dev_type = models.IntegerField('设备类型', choices=Device.DEV_TEMP_TYPE_CHOICES)
    action = models.IntegerField('动作', choices=ACTION_CHOICES)

    class Meta:
        verbose_name = '终端运行日志'

    def __str__(self):
        return '{} {}'.format(self.id, self.action)


class StrategyDistributionStatusLog(Log):
    HANDLE_STATUS_CHOICE = (
        (1, '登录'),
        (2, '授权'),
        (3, '管理'),
    )

    dev_name = models.CharField('设备名称', max_length=20)
    dev_type = models.IntegerField('设备类型', choices=Device.DEV_TEMP_TYPE_CHOICES)
    distribute_time = models.DateTimeField('策略下发时间', null=True)
    distribute_status = models.IntegerField('策略下发状态')
    handle_time = models.DateTimeField('处理时间', null=True)
    dev_handle_status = models.IntegerField('终端处理状态',
                                            choices=HANDLE_STATUS_CHOICE)

    class Meta:
        verbose_name = '策略下发状态日志'

    def __str__(self):
        return '{} {}'.format(self.id, self.content[0:20])


class ReportLog(models.Model):
    """
    统计报表信息
    """

    occurred_time = models.DateTimeField('生成时间', default=timezone.now)
    start_time = models.DateTimeField('起始时间', default=timezone.now)
    end_time = models.DateTimeField('结束时间', default=timezone.now)
    alert_count = models.IntegerField('告警数量', null=True)
    auditor_alert_count = models.IntegerField('审计告警数量', null=True)
    firewall_alert_count = models.IntegerField('防火墙告警数量', null=True)
    sys_alert_count = models.IntegerField('系统告警数量', null=True)
    device_alert_count = models.IntegerField('资产告警数量', null=True)

    alert_per = models.IntegerField('告警处理完成率', null=True)
    auditor_alert_per = models.IntegerField('审计告警处理完成率', null=True)
    firewall_alert_per = models.IntegerField('防火墙告警处理完成率', null=True)
    sys_alert_per = models.IntegerField('系统告警处理完成率', null=True)
    device_alert_per = models.IntegerField('资产告警处理完成率', null=True)

    sec_device_add = models.IntegerField('安全资产新增数量', null=True)
    com_device_add = models.IntegerField('网络设备新增数量', null=True)
    ser_device_add = models.IntegerField('主机设备新增数量', null=True)
    con_device_add = models.IntegerField('工控设备新增数量', null=True)

    unified_log_count = models.IntegerField('本机日志数量', null=True)
    auditor_log_count = models.IntegerField('审计日志数量', null=True)
    firewall_log_count = models.IntegerField('防火墙日志数量', null=True)
    login_account_count = models.IntegerField('登录账户数量', null=True)

    class Meta:
        verbose_name = '统计的报表信息'
        ordering = ['-id']

    def __str__(self):
        return '{} {}'.format(self.id, self.occurred_time)


class DeviceAllAlert(Log):
    FIREWALL_ACTION_PASS = 0
    FIREWALL_ACTION_WARNING = 1
    FIREWALL_ACTION_DROP = 2
    FIREWALL_ACTION_BLOCK = 3

    FIREWALL_ACTION_CHOICES = (
        (FIREWALL_ACTION_PASS, '通过'),
        (FIREWALL_ACTION_WARNING, '告警'),
        (FIREWALL_ACTION_DROP, '丢弃'),
        (FIREWALL_ACTION_BLOCK, '阻断'),
    )

    STATUS_UNREAD = 0
    STATUS_READ = 1

    READ_STATUS_CHOICES = (
        (STATUS_READ, '已读'),
        (STATUS_UNREAD, '未读'),
    )

    STATUS_UNRESOLVED = 0
    STATUS_RESOLVED = 1

    RESOLVED_STATUS_CHOICES = (
        (STATUS_UNRESOLVED, '未处理'),
        (STATUS_RESOLVED, '已处理'),
    )

    # 扫描探测
    TYPE_PORT_SCAN = 1
    TYPE_WEB_SCAN = 2
    TYPE_MALICIOUS_SCAN = 3
    # 漏洞利用
    TYPE_SQL = 4
    TYPE_OVERFLOW = 5
    TYPE_COMMAND = 6
    TYPE_XSS = 7
    TYPE_PASSWORD = 8
    TYPE_AUTHORITY = 9
    # 后期渗透
    TYPE_SYSTEM_PRIVILEGE = 10
    TYPE_HORIZONTAL_SYSTEM = 11
    TYPE_ERASE = 12
    # APT
    TYPE_TROJAN_ATTACK = 14
    TYPE_TROJAN_BACK = 15
    TYPE_ZOMBIE = 16
    TYPE_WORM = 17
    # 其他
    TYPE_DOS = 18
    TYPE_ARP = 19
    TYPE_MALICIOUS_OPERATION = 20

    TYPE_CHOICES = (
        # 扫描探测
        (TYPE_PORT_SCAN, '端口扫描'),
        (TYPE_WEB_SCAN, 'web扫描'),
        (TYPE_MALICIOUS_SCAN, '恶意扫描'),
        (TYPE_PASSWORD, '暴力破解'),
        # 漏洞利用
        (TYPE_SQL, 'sql注入'),
        (TYPE_OVERFLOW, '溢出攻击'),
        (TYPE_COMMAND, '命令注入'),
        (TYPE_XSS, 'xss攻击'),
        (TYPE_AUTHORITY, '获取权限'),
        # 后期渗透
        (TYPE_SYSTEM_PRIVILEGE, '系统提权'),
        (TYPE_HORIZONTAL_SYSTEM, '横向系统'),
        (TYPE_ERASE, '擦除痕迹'),
        # APT
        (TYPE_TROJAN_ATTACK, '木马攻击'),
        (TYPE_TROJAN_BACK, '木马回连'),
        (TYPE_ZOMBIE, '僵尸网络'),
        (TYPE_WORM, '蠕虫攻击'),
        # 其他
        (TYPE_DOS, 'DOS攻击'),
        (TYPE_ARP, 'ARP欺骗'),
        (TYPE_MALICIOUS_OPERATION, '恶意操作'),
    )

    CATEGORY_SCAN = 1
    CATEGORY_FLAW = 2
    CATEGORY_PENETRATION = 3
    CATEGORY_APT = 4
    CATEGORY_OTHER = 5

    EVENT_CATEGORY_CHOICE = (
        (CATEGORY_SCAN, '探测扫描'),
        (CATEGORY_FLAW, '漏洞利用'),
        (CATEGORY_PENETRATION, '后期渗透'),
        (CATEGORY_APT, 'APT'),
        (CATEGORY_OTHER, '其他')
    )
    SCAN_TYPE = [TYPE_PORT_SCAN, TYPE_WEB_SCAN, TYPE_MALICIOUS_SCAN, TYPE_PASSWORD]
    FLAW_TYPE = [TYPE_SQL, TYPE_OVERFLOW, TYPE_COMMAND, TYPE_XSS, TYPE_AUTHORITY]
    PENETRATION_TYPE = [TYPE_SYSTEM_PRIVILEGE, TYPE_HORIZONTAL_SYSTEM, TYPE_ERASE]
    APT_TYPE = [TYPE_TROJAN_ATTACK, TYPE_TROJAN_BACK, TYPE_ZOMBIE, TYPE_WORM]
    OTHER_TYPE = [TYPE_DOS, TYPE_ARP, TYPE_MALICIOUS_OPERATION]

    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3

    LEVEL_CHOICE = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    device = models.ForeignKey(Device, null=True, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.SET_NULL, blank=True, null=True,
                             verbose_name='处理人')
    event_log = models.ForeignKey(EventLog, models.SET_NULL, blank=True,
                                  null=True, verbose_name='对应的安全事件编号')
    name = models.CharField('事件名称', max_length=50, blank=True, null=True)
    category = models.IntegerField('告警类别', choices=EVENT_CATEGORY_CHOICE)
    type = models.IntegerField('告警类型', choices=TYPE_CHOICES)
    level = models.IntegerField('事件级别', choices=LEVEL_CHOICE, default=0)
    desc = models.CharField('事件特征描述', max_length=80, blank=True, null=True)
    log_desc = models.CharField('日志描述', max_length=80, blank=True, null=True)
    sec_desc = models.CharField('告警描述', max_length=2000, blank=True, null=True)
    example_desc = models.CharField('举例子', max_length=80, blank=True, null=True)
    suggest_desc = models.TextField('处理建议', blank=True, null=True)
    origin_mac = models.CharField('原MAC地址', max_length=32,
                                  validators=[MACAddrValidator], null=True)
    conflict_mac = models.CharField('冲突MAC地址', max_length=32,
                                    validators=[MACAddrValidator], null=True)

    src_ip = models.GenericIPAddressField('源IP地址', blank=True, null=True)
    dst_ip = models.GenericIPAddressField('目的IP地址', blank=True, null=True)
    src_mac = models.CharField('源mac地址', validators=[MAC_VALIDATOR],
                               max_length=32, blank=True, null=True)
    dst_mac = models.CharField('目标mac地址', validators=[MAC_VALIDATOR],
                               max_length=32, blank=True, null=True)
    dst_port = models.IntegerField('目的端口', null=True,
                                   validators=[MinValueValidator(1),
                                               MaxValueValidator(65535)])
    src_port = models.IntegerField('源端口', null=True,
                                   validators=[MinValueValidator(1),
                                               MaxValueValidator(65535)])
    protocol = models.CharField('协议', max_length=32, blank=True, null=True)

    device_ip = ArrayField(models.GenericIPAddressField(),
                           verbose_name='关联设备IP', null=True)
    illegal_ip = ArrayField(models.GenericIPAddressField(), verbose_name='非法IP',
                            null=True)
    illegal_port = ArrayField(models.IntegerField('源端口', validators=[
        MinValueValidator(1), MaxValueValidator(65535)]),
                              verbose_name='非法端口', null=True)
    first_at = models.DateTimeField('首次发生时间', null=True)
    last_at = models.DateTimeField('最近发生时间', null=True)
    updated_at = models.DateTimeField('记录更新时间', auto_now=True)
    count = models.IntegerField('重复次数', default=1)
    other_info = JSONField(encoder=DjangoJSONEncoder, null=True)
    content = models.CharField('内容', max_length=1000, null=True, blank=True)

    # 以下是防火墙安全事件列表
    app_layer_protocol = models.CharField('应用层协议', max_length=32, blank=True,
                                          null=True)
    packet_length = models.IntegerField('包长度', blank=True, null=True)
    signature_msg = models.CharField('备注', max_length=1024, blank=True,
                                     null=True)
    matched_key = models.CharField('规则项', max_length=1024, blank=True,
                                   null=True)
    protocol_detail = models.CharField('协议细节', max_length=1024, blank=True,
                                       null=True)
    packet = models.TextField('原始数据包内容', max_length=1024, blank=True, null=True)
    alert_type = models.IntegerField('告警类型', default=0)
    status = models.IntegerField('读取状态', choices=READ_STATUS_CHOICES,
                                 default=STATUS_UNREAD)

    des_resolved = models.TextField('处理备注', max_length=1024, blank=True,
                                    null=True)
    status_resolved = models.IntegerField('处理状态',
                                          choices=RESOLVED_STATUS_CHOICES,
                                          default=STATUS_UNRESOLVED)
    time_resolved = models.DateTimeField('处理时间', null=True)
    action = models.IntegerField('动作', choices=FIREWALL_ACTION_CHOICES,
                                 default=FIREWALL_ACTION_PASS)
    src_country = models.CharField('源国家', max_length=100, null=True)
    src_province = models.CharField('源省份', max_length=100, null=True)
    src_city = models.CharField('源城市', max_length=100, null=True)
    src_latitude = models.FloatField('源纬度', null=True)
    src_longitude = models.FloatField('源经度', null=True)
    src_private = models.BooleanField('是否是内网', default=True)
    dst_country = models.CharField('目的国家', max_length=100, null=True)
    dst_province = models.CharField('目的省份', max_length=100, null=True)
    dst_city = models.CharField('目的城市', max_length=100, null=True)
    dst_latitude = models.FloatField('目的纬度', null=True)
    dst_longitude = models.FloatField('目的经度', null=True)
    dst_private = models.BooleanField('是否是内网', default=True)


    class Meta:
        verbose_name = '设备所有告警'
        ordering = ['id']

    def __str__(self):
        return '{} {}'.format(self.id, self.get_type_display())


class FileLog(models.Model):
    name = models.CharField('保存文件 name', max_length=80, null=True, unique=True)
    file = models.FileField('这是所有需要返回下载的文件', null=True)
    occurred_time = models.DateTimeField('文件的生成时间', default=timezone.now)
    upload = models.FileField(upload_to='uploads/%Y/%m/%d/')

    def __str__(self):
        return '{}'.format(self.id)


class SecurityEvent(models.Model):
    """
    对综管平台的操作或综管定时任务检测出的问题，都会放在安全事件里
    """
    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3

    LEVEL_CHOICE = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    CATEGORY_LOCAL = 1
    CATEGORY_OPERATION = 2

    CATEGORY_CHOICES = (
        (CATEGORY_LOCAL, '本地事件'),
        (CATEGORY_OPERATION, '运营事件'),
    )

    TYPE_OPERATION = 1
    TYPE_USER = 2
    TYPE_SECURITY = 3
    TYPE_ASSETS = 4
    TYPE_ABNORMAL = 5
    TYPE_SYSTEM = 6

    TYPE_CHOICES = (
        (TYPE_OPERATION, '操作事件'),
        (TYPE_USER, '用户管理'),
        (TYPE_SECURITY, '安全告警'),
        (TYPE_ASSETS, '资产告警'),
        (TYPE_ABNORMAL, '异常告警'),
        (TYPE_SYSTEM, '系统事件'),
    )

    STATUS_UNRESOLVED = 0
    STATUS_RESOLVED = 1

    RESOLVED_STATUS_CHOICES = (
        (STATUS_UNRESOLVED, '未处理'),
        (STATUS_RESOLVED, '已处理'),
    )

    CATEGORY_LOCAL_TYPES = [TYPE_OPERATION, TYPE_USER, TYPE_SYSTEM]
    CATEGORY_OPERATION_TYPES = [TYPE_SECURITY, TYPE_ABNORMAL, TYPE_ASSETS]

    device = models.ForeignKey(Device, null=True, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.SET_NULL, blank=True, null=True,
                             verbose_name='处理人')
    level = models.IntegerField('威胁级别', choices=LEVEL_CHOICE)
    category = models.IntegerField('事件类别', choices=CATEGORY_CHOICES)
    type = models.IntegerField('事件类型', choices=TYPE_CHOICES)
    occurred_time = models.DateTimeField('告警时间', default=timezone.now,
                                         null=True)
    content = models.CharField('事件描述', max_length=10000, blank=True, null=True)
    status_resolved = models.IntegerField(
        '处理状态', choices=RESOLVED_STATUS_CHOICES, default=STATUS_UNRESOLVED)
    des_resolved = models.TextField('处理备注', max_length=1024, blank=True,
                                    null=True)
    time_resolved = models.DateTimeField('处理时间', null=True)

    class Meta:
        verbose_name = '安全事件'
        ordering = ('-id',)


class AlertDistribution(models.Model):
    scan = models.PositiveIntegerField('扫描探测')
    flaw = models.PositiveIntegerField('漏洞利用')
    penetration = models.PositiveIntegerField('后期渗透')
    apt = models.PositiveIntegerField('APT')
    other = models.PositiveIntegerField('其他')
    update_time = models.DateTimeField('更新时间')

    class Meta:
        verbose_name = '安全威胁分布'
        ordering = ('-id',)


class IncrementDistribution(models.Model):
    scan = models.PositiveIntegerField('扫描探测')
    flaw = models.PositiveIntegerField('漏洞利用')
    penetration = models.PositiveIntegerField('后期渗透')
    apt = models.PositiveIntegerField('APT')
    other = models.PositiveIntegerField('其他')
    update_time = models.DateTimeField('更新时间')

    class Meta:
        verbose_name = '安全威胁分布，增加数据'
        ordering = ('-update_time',)