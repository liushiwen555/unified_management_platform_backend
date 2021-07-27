from django.contrib.postgres.fields import ArrayField, JSONField
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.db import models
from django.utils import timezone

from base_app.models import BaseStrategy, TerminalLog, Device, AuditorStrategy
from utils.core.mixins import UniqueAttrMixin
from utils.validators import MAC_VALIDATOR
from log.models import DeviceAllAlert

MACAddrValidator = RegexValidator(regex=r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$',
                                  message='Enter a valid MAC address, for example "12:AD:34:EC:4D:1B".')


class AuditWhiteListStrategy(AuditorStrategy):
    """
        审计白名单策略表：
        'id':             记录id，主键
        'name':           名称，char
        'src_ip':         源IP地址，IPAddress
        'src_ports':      源端口，[[min, max], ..., [min, max]], min=max代表单一端口, []代表any端口
        'dst_ip':         目的IP地址，IPAddress
        'dst_ports':      目的端口，[[min, max], ..., [min, max]], min=max代表单一端口, []代表any端口
        'protocol':       协议
        'rule':           功能码规则
        'level':          威胁等级，int，1-3
        'is_learned':     是否是自学习来的
        'is_active':      激活状态，bool
        """

    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3
    LEVEL_CHOICE = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    SOURCE_CHOICE = (
        (1, '用户添加'),
        (2, '其他'),
    )

    name = models.CharField('名称', max_length=20, null=True)
    src_ip = models.GenericIPAddressField('源IP地址')
    src_ports = ArrayField(
        ArrayField(models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)]), size=2),
        verbose_name='源端口', null=True)
    dst_ip = models.GenericIPAddressField('目的IP地址')
    dst_ports = ArrayField(
        ArrayField(models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)]), size=2),
        verbose_name='目的端口', null=True)
    protocol = models.CharField('协议', max_length=32, blank=True, null=True)
    rule = JSONField('规则', encoder=DjangoJSONEncoder, null=True)
    level = models.IntegerField('威胁等级', choices=LEVEL_CHOICE, default=1)
    source = models.IntegerField('白名单来源', choices=SOURCE_CHOICE, default=1)
    is_learned = models.BooleanField('是否自学习', default=False)
    is_active = models.BooleanField('激活状态', default=False)

    class Meta:
        verbose_name = '白名单'
        ordering = ['-created_time']

    def __str__(self):
        return '{} {}'.format(self.id, self.name)


class AuditorBlackList(models.Model):
    """
    审计的黑名单库（审计设备和模板生成时的黑名单策略来源）
    'id':             记录id，主键
    'sid':            snort规则sid, int
    'rule':           snort规则
    'level':          风险等级, int
    'category':       类型, char
    'name':           名称, char
    'description':    描述, chat
    'vulnerable':     影响范围, char
    'requirement':    攻击条件, char
    'effect':         威胁, char
    'suggest':        建议, char
    'cve':            CVE编号, char
    'publish_date':   发布日期, date
    'is_active':      激活状态, bool
    """

    LEVEL_CHOICE = (
        (1, '低'),
        (2, '中'),
        (3, '高'),
    )

    SOURCE_CHOICE = (
        (1, 'CNNVD'),
        (2, 'CVE'),
        (3, 'OTHER'),
    )

    sid = models.IntegerField('snort规则sid', validators=[MinValueValidator(1000000)])
    rule = models.CharField('snort规则', max_length=10000)
    level = models.IntegerField('风险等级', choices=LEVEL_CHOICE)
    category = models.CharField('类型', max_length=20)
    alert_category = models.IntegerField(
        '安全威胁类别', choices=DeviceAllAlert.EVENT_CATEGORY_CHOICE)
    alert_type = models.IntegerField(
        '安全威胁类型', choices=DeviceAllAlert.TYPE_CHOICES)
    name = models.CharField('名称', max_length=100)
    description = models.CharField('描述', max_length=10000)
    vulnerable = models.CharField('影响范围', max_length=10000)
    requirement = models.CharField('攻击条件', max_length=100)
    effect = models.CharField('威胁', max_length=100)
    suggest = models.CharField('建议', max_length=10000)
    cve = models.CharField('CVE编号', max_length=20)
    cnnvd = models.CharField('CNNVD编号', max_length=20, default='')
    source = models.IntegerField('漏洞来源', choices=SOURCE_CHOICE, default=3)
    publish_date = models.DateField('发布日期')
    is_active = models.BooleanField('激活状态', default=False)

    class Meta:
        verbose_name = '黑名单'
        ordering = ['id']

    def __str__(self):
        return '{} {}'.format(self.sid, self.name)


class AuditBlackListStrategy(AuditorStrategy):
    """
    审计黑名单表：
    'id':             记录id，主键
    'sid':            snort规则sid, int
    'rule':           snort规则
    'level':          风险等级, int
    'category':       类型, char
    'name':           名称, char
    'description':    描述, chat
    'vulnerable':     影响范围, char
    'requirement':    攻击条件, char
    'effect':         威胁, char
    'suggest':        建议, char
    'cve':            CVE编号, char
    'publish_date':   发布日期, date
    'is_active':      激活状态, bool
    """

    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3
    LEVEL_CHOICE = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    SOURCE_CHOICE = (
        (1, 'CNNVD'),
        (2, 'CVE'),
        (3, 'OTHER'),
    )

    sid = models.IntegerField('snort规则sid', validators=[MinValueValidator(100000)])
    rule = models.CharField('snort规则', max_length=10000)
    level = models.IntegerField('风险等级', choices=LEVEL_CHOICE, default=1)
    category = models.CharField('类型', max_length=20)
    alert_category = models.IntegerField(
        '安全威胁类别', choices=DeviceAllAlert.EVENT_CATEGORY_CHOICE)
    alert_type = models.IntegerField(
        '安全威胁类型', choices=DeviceAllAlert.TYPE_CHOICES)
    name = models.CharField('名称', max_length=100)
    description = models.CharField('描述', max_length=10000)
    vulnerable = models.CharField('影响范围', max_length=10000, blank=True)
    requirement = models.CharField('攻击条件', max_length=100, blank=True)
    effect = models.CharField('威胁', max_length=100, blank=True)
    suggest = models.CharField('建议', max_length=10000, blank=True)
    cve = models.CharField('CVE编号', max_length=20, blank=True)
    cnnvd = models.CharField('CNNVD编号', max_length=20, default='', null=True, blank=True)
    source = models.IntegerField('漏洞来源', choices=SOURCE_CHOICE, default=3)
    publish_date = models.DateField('发布日期', null=True)
    is_active = models.BooleanField('激活状态', default=False)

    class Meta:
        verbose_name = '黑名单'
        ordering = ['id']

    def __str__(self):
        return '{} {}'.format(self.sid, self.name)


class AuditIPMACBondStrategy(UniqueAttrMixin, AuditorStrategy):
    """
    审计设备ip_mac绑定策略表：
    'id':             记录id，主键
    'dev_name':       名称，char
    'ip':             IP地址，IPAddress
    'mac':            MAC地址，char
    'ip_mac_bond':    是否绑定IP MAC，bool
    """
    name = models.CharField('设备名称', max_length=20, blank=True)
    ip = models.GenericIPAddressField('IP地址')
    mac = models.CharField('MAC地址', max_length=32, validators=[MAC_VALIDATOR])
    ip_mac_bond = models.BooleanField('是否绑定IP MAC', default=False)

    unique_attr_list = ['ip', 'mac']

    class Meta:
        verbose_name = '设备'
        ordering = ['-created_time']
        unique_together = (('device', 'ip',),)

    def __str__(self):
        return '{} {}'.format(self.id, self.name)


class AuditSecAlert(TerminalLog):
    """
    审计设备安全告警
    'id':             记录id,主键
    'category':       类别, int 1黑名单 2非法IP接入 3非法端口 4MAC不符 5S7协议下载
    'level':          威胁级别, int 1-3
    'src_ip':         源IP地址,IPAddress
    'src_port':       源端口,int 1-65535
    'dst_ip':         目的IP地址,IPAddress
    'dst_port':       目的端口,int 1-65535
    'protocol':       协议,char
    'device_ip':      关联设备IP,array
    'illegal_ip':     非法IP,array
    'illegal_port':   非法端口,array
    'first_at':       首次发生时间,datetime
    'last_at':        最近发生时间,datetime
    'updated_at':     记录更新时间,datetime
    'count':          重复次数,int
    'other_info':     其它信息,json
    """

    CATEGORY_BLACKLIST = 1
    CATEGORY_ILLEGAL_IP = 2
    CATEGORY_ILLEGAL_FLOW = 3
    CATEGORY_MAC_NOT_MATCH = 4
    CATEGORY_ICS = 5
    CATEGORY_NO_TRAFFIC = 30

    CATEGORY_CHOICE = (
        (CATEGORY_BLACKLIST, '黑名单告警'),
        (CATEGORY_ILLEGAL_IP, '资产异常告警（陌生设备接入）'),
        (CATEGORY_ILLEGAL_FLOW, '白名单告警（通讯行为异常）'),
        (CATEGORY_MAC_NOT_MATCH, '资产异常告警(Mac地址冲突)'),
        (CATEGORY_ICS, '白名单告警（通讯内容异常）'),
        (CATEGORY_NO_TRAFFIC, '资产异常告警（设备离线）'),
    )

    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3

    LEVEL_CHOICE = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    category = models.IntegerField('类型', choices=CATEGORY_CHOICE, help_text=f'可选范围：{CATEGORY_CHOICE}')
    level = models.IntegerField('威胁级别', choices=LEVEL_CHOICE, default=LEVEL_HIGH, help_text=f'可选范围：{LEVEL_CHOICE}')

    src_mac = models.CharField('源MAC地址', max_length=32, validators=[MACAddrValidator], null=True)
    src_ip = models.GenericIPAddressField('源IP地址', null=True)
    src_port = models.IntegerField('源端口', null=True, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    dst_mac = models.CharField('目的MAC地址', max_length=32, validators=[MACAddrValidator], null=True)
    dst_ip = models.GenericIPAddressField('目的IP地址', null=True)
    dst_port = models.IntegerField('目的端口', null=True, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    origin_mac = models.CharField('原MAC地址', max_length=32, validators=[MACAddrValidator], null=True)
    conflict_mac = models.CharField('冲突MAC地址', max_length=32, validators=[MACAddrValidator], null=True)
    protocol = models.CharField('协议', max_length=32, null=True)
    device_ip = ArrayField(models.GenericIPAddressField(), verbose_name='关联设备IP', null=True)
    illegal_ip = ArrayField(models.GenericIPAddressField(), verbose_name='非法IP', null=True)
    illegal_port = ArrayField(models.IntegerField('源端口', validators=[MinValueValidator(1), MaxValueValidator(65535)]),
                              verbose_name='非法端口', null=True)
    last_at = models.DateTimeField('最近发生时间')
    count = models.IntegerField('重复次数', default=1)
    other_info = JSONField(encoder=DjangoJSONEncoder, null=True)

    first_at = models.DateTimeField('首次发生时间')
    updated_at = models.DateTimeField('记录更新时间', auto_now=True)

    class Meta:
        verbose_name = '安全告警'
        ordering = ['-last_at']

    def __str__(self):
        return '{} {}'.format(self.id, self.get_category_display())


class AuditSysAlert(TerminalLog):
    """
    审计设备系统事件，原审计系统告警以及系统日志
    'id':             记录id,主键
    'category':       类型, int 1CPU告警 2存储告警
    'device_type':    设备类型, int 1CPU 2存储
    'level':          威胁级别, int 1-3
    """

    CATEGORY_ALERT_CPU = 1
    CATEGORY_ALERT_STORAGE = 2
    CATEGORY_LOG_LOGIN = 3
    CATEGORY_LOG_STRATEGY_EDIT = 4
    CATEGORY_LOG_USER_MANAGEMENT = 5
    CATEGORY_LOG_PLATFORM_OPERATION = 6
    CATEGORY_LOG_STORAGE_CLEAR = 7
    CATEGORY_LOG__AUDITOR = 8

    CATEGORY_CHOICE = (
        (CATEGORY_ALERT_CPU, '运行告警（CPU）'),
        (CATEGORY_ALERT_STORAGE, '运行告警（存储）'),
        (CATEGORY_LOG_LOGIN, '运行日志（登录登出）'),
        (CATEGORY_LOG_STRATEGY_EDIT, '运行日志（策略编辑）'),
        (CATEGORY_LOG_USER_MANAGEMENT, '运行日志（用户管理）'),
        (CATEGORY_LOG_PLATFORM_OPERATION, '运行日志（平台操作）'),
        (CATEGORY_LOG_STORAGE_CLEAR, '运行日志（存储）'),
        (CATEGORY_LOG__AUDITOR, '运行日志（审计记录）')
    )

    LEVEL_CHOICE = (
        (1, '低'),
        (2, '中'),
        (3, '高'),
    )

    category = models.IntegerField('类型', choices=CATEGORY_CHOICE)
    level = models.IntegerField('威胁级别', choices=LEVEL_CHOICE, default=1)
    user = models.CharField('用户名', max_length=20, blank=True, null=True)
    ip = models.GenericIPAddressField('IP地址', null=True)
    content = models.CharField('内容', max_length=1000, blank=True, null=True)


    class Meta:
        verbose_name = '系统告警'
        ordering = ['-occurred_time']

    def __str__(self):
        return '{} {}'.format(self.id, self.get_category_display())


class AuditLog(TerminalLog):
    """
    审计日志
    'id':             记录id,主键
    'category':       类别, int 1登录登出 2规则变更 3用户操作 4平台操作
    'user':           用户名, char
    'ip':             IP地址, IPaddr
    """

    CATEGORY_CHOICE = (
        (1, '运行日志（登录登出）'),
        (2, '运行日志（策略编辑）'),
        (3, '运行日志（用户管理）'),
        (4, '运行日志（平台操作）'),
        (5, '运行日志（存储）'),
    )

    category = models.IntegerField('类型', choices=CATEGORY_CHOICE)
    user = models.CharField('用户名', max_length=20)
    ip = models.GenericIPAddressField('IP地址')

    class Meta:
        verbose_name = '日志'
        ordering = ['-occurred_time']

    def __str__(self):
        return '{} {}'.format(self.id, self.get_category_display())


class TimeScaleAuditLog(models.Model):
    """
    日志
    'id':             记录id,主键
    'category':       类别, int 1登录登出 2规则变更 3用户操作 4平台操作
    'user':           用户名, char
    'ip':             IP地址, IPaddr
    """

    CATEGORY_CHOICE = (
        (1, '登录登出'),
        (2, '规则变更'),
        (3, '用户操作'),
        (4, '平台操作'),
        (5, '存储空间释放'),
    )

    # device = models.ForeignKey(Device, on_delete=models.CASCADE)
    occurred_time = models.DateTimeField('发生时间', default=timezone.now)
    is_read = models.BooleanField('是否已读', default=False)
    read_time = models.DateTimeField('阅读时间', null=True)
    content = models.CharField('内容', max_length=1000, blank=True)
    category = models.IntegerField('类型', choices=CATEGORY_CHOICE)
    user = models.CharField('用户名', max_length=20)
    ip = models.GenericIPAddressField('IP地址')

    class Meta:
        verbose_name = '日志'
        ordering = ['-occurred_time']
        managed = False

    def __str__(self):
        return '{} {}'.format(self.id, self.get_category_display())


class RiskCountry(models.Model):
    country = models.CharField('国家', max_length=200)
    count = models.PositiveIntegerField('通信次数')
    update_time = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '安全态势中心——威胁源地区TOP5'
        ordering = ('-count', )


class AttackIPStatistic(models.Model):
    count = models.PositiveIntegerField('攻击次数', default=0)
    src_ip = models.PositiveIntegerField('攻击源IP个数', default=0)
    foreign = models.PositiveIntegerField('境外访问个数', default=0)
    external_ip = models.PositiveIntegerField('外网访问IP个数', default=0)
    update_time = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = '安全态势——攻击统计'
