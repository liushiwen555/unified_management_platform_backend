from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.forms import model_to_dict
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from unified_log.models import LogProcessTemplate
from utils.helper import random_string, get_subclasses
from utils.validators import MAC_VALIDATOR
from utils.core.field_error import AssetsField

MODEL_TO_DICT_EXCLUDE = ['device', 'id', 'template']

REGISTER_CODE_LEN = 8
SECRET_LEN = 64


def get_device_strategy_subclasses(dev_type):
    """
    获取某类型设备下的所有策略类
    :param dev_type: int, 设备类型
    :return:
    """
    if dev_type == Device.FIRE_WALL:
        return get_subclasses(FirewallStrategy)
    elif dev_type == Device.AUDITOR:
        return get_subclasses(AuditorStrategy)


def get_device_applicable_strategy_subclasses(dev_type):
    """
    获取某类型设备下的所有可下发的策略类（有些类型的策略是不能下发的，比如终端设备通过自学习得到的策略）
    :param dev_type:
    :return:
    """
    if dev_type == Device.FIRE_WALL:
        result = [item for item in get_subclasses(FirewallStrategy) if
                  item.applicable]
        return result
    elif dev_type == Device.AUDITOR:
        result = [item for item in get_subclasses(AuditorStrategy) if
                  item.applicable]
        return result


class Device(models.Model):
    """
    设备表
    'name':                     设备名，char
    'type':                     设备类型，int
    'location':                 设备位置，char
    'ip':                       ip地址，ip
    'version':                  版本，char
    'responsible_user':         责任人，char
    'register_code':            注册码，char
    'status':                   设备状态，int
    'registered_time':          注册时间，datetime
    'audit_sec_alert_max_id':   审计设备安全告警的最大id，int
    'audit_sys_alert_max_id':   审计设备系统告警的最大id，int
    'audit_log_max_id':         审计设备log的最大id, int
    'strategy_apply_status':    当前策略是否已下发, bool
    'apply_time':               策略下发时间, datetime
    'secret':                   策略下发时间, char
    'template_name':            设备应用的模板名, char
    'log_template':             设备应用的日志解析模板, LogProcessTemplate
    """

    TYPE_UNKNOWN = 0
    FIRE_WALL = 1
    AUDITOR = 2
    GATEKEEPER = 3
    IDS = 4
    IPS = 5
    SCANNER = 6

    EXCHANGER = 7
    ROUTER = 8

    WORKSERVER = 9
    WORKSTATION = 10
    SERVER = 11

    PLC = 12

    DEV_TEMP_TYPE_CHOICES = (
        (FIRE_WALL, '防火墙'),
        (AUDITOR, '审计'),
        (GATEKEEPER, '网闸'),
        (IDS, 'IDS'),
        (IPS, 'IPS'),
        (SCANNER, '漏洞扫描'),
        (EXCHANGER, '交换机'),
        (ROUTER, '路由器'),
        (WORKSERVER, '工作主机'),
        (WORKSTATION, '工作站'),
        (SERVER, '服务器'),
        (PLC, 'PLC'),
        (TYPE_UNKNOWN, '其他'),
    )

    CATEGORY_Security = 1
    CATEGORY_Communication = 2
    CATEGORY_Sever = 3
    CATEGORY_Control = 4
    CATEGORY_Other = 99

    CATEGORY_CHOICE = (
        (CATEGORY_Security, '安全资产'),
        (CATEGORY_Communication, '网络资产'),
        (CATEGORY_Sever, '主机资产'),
        (CATEGORY_Control, '工控资产'),
    )

    CATEGORY_TYPES = {
        CATEGORY_Security: [TYPE_UNKNOWN, FIRE_WALL, AUDITOR, GATEKEEPER, IDS,
                            IPS, SCANNER],
        CATEGORY_Communication: [EXCHANGER, ROUTER, TYPE_UNKNOWN],
        CATEGORY_Sever: [WORKSERVER, WORKSTATION, TYPE_UNKNOWN, SERVER],
        CATEGORY_Control: [PLC, TYPE_UNKNOWN],
    }

    VALUE_CHOICE = (
        (1, '低'),
        (2, '中'),
        (3, '高'),
    )

    ONLINE = 1
    OFFLINE = 2

    REGISTERED = 1
    NOT_REGISTERED = 2

    STATUS_CHOICES = (
        (ONLINE, '在线'),
        (OFFLINE, '离线'),
    )

    REGISTER_CHOICES = (
        (REGISTERED, '注册'),
        (NOT_REGISTERED, '未注册'),
    )

    ON = 1
    OFF = 2
    # 为了监控设备离线与在线状态切换时，能否产生告警
    STATUS_ALERT_CHOICES = (
        (ON, '可告警'),
        (OFF, '不可告警'),
    )

    STRATEGY_APPLY_STATUS_UN_APPLIED = 1
    STRATEGY_APPLY_STATUS_APPLYING = 2
    STRATEGY_APPLY_STATUS_FAILED = 3
    STRATEGY_APPLY_STATUS_APPLIED = 4

    STRATEGY_APPLY_STATUS_CHOICES = (
        (STRATEGY_APPLY_STATUS_UN_APPLIED, '未应用'),
        (STRATEGY_APPLY_STATUS_APPLYING, '应用中'),
        (STRATEGY_APPLY_STATUS_FAILED, '应用失败'),
        (STRATEGY_APPLY_STATUS_APPLIED, '已应用'),
    )

    name = models.CharField(
        '资产名称', max_length=16, unique=True, help_text='资产名称',
        error_messages={
            'unique': AssetsField.NAME_DUPLICATE,
        })
    category = models.IntegerField('资产类别', choices=CATEGORY_CHOICE,
                                   help_text='资产类别', null=True)
    value = models.IntegerField('重要程度', choices=VALUE_CHOICE, default=1,
                                help_text='重要程度', null=True)
    ip = models.GenericIPAddressField(
        'ip', unique=True, error_messages={
            'unique': AssetsField.IP_DUPLICATE,
            'invalid': AssetsField.IP_VALIDATOR_ERROR
        })
    mac = models.CharField('MAC地址', max_length=32, validators=[MAC_VALIDATOR],
                           null=True, unique=True,
                           error_messages={'unique': '资产MAC地址重复'})
    ip_mac_bond = models.BooleanField('是否绑定IP&MAC', default=False,
                                      help_text='IP&MAC绑定状态')
    monitor = models.BooleanField('监控开关', default=False, help_text='性能监控状态')
    responsible_user = models.CharField('安全负责人', max_length=10, blank=True,
                                        help_text='安全负责人')
    location = models.CharField('资产位置', max_length=10, blank=True,
                                help_text='资产位置')
    created_at = models.DateTimeField('资产添加时间', auto_now_add=True)
    description = models.CharField('备注信息', max_length=100, blank=True)

    # 以下都是资产详情里的内容
    hardware = models.CharField('资产型号', max_length=10, blank=True, null=True)
    brand = models.CharField('品牌', max_length=10, blank=True, null=True)
    version = models.CharField('版本号', max_length=10, null=True, blank=True)
    software = models.CharField('软件版本', max_length=10, blank=True)
    last_update_time = models.DateTimeField('最近更新时间', null=True)
    last_online_time = models.DateTimeField('最近上线时间', null=True)

    # 以下是旧 model 所带内容
    links = models.ManyToManyField('self', verbose_name='拓扑中连接的其它设备',
                                   blank=True)
    type = models.IntegerField('资产类型', choices=DEV_TEMP_TYPE_CHOICES,
                               help_text='资产类型', null=True)
    register_code = models.CharField('注册码', max_length=20)
    status = models.IntegerField('在线状态', choices=STATUS_CHOICES,
                                 default=OFFLINE, help_text='在线状态')

    register_status = models.IntegerField('关联状态', choices=REGISTER_CHOICES,
                                          default=NOT_REGISTERED)
    alert_status = models.BooleanField('是否可以报离线告警', default=False)

    registered_time = models.DateTimeField('注册时间', null=True)
    audit_sec_alert_max_id = models.IntegerField('审计设备安全告警的最大id', default=1)
    audit_sys_alert_max_id = models.IntegerField('审计设备系统告警的最大id', default=1)
    audit_protocol_max_id = models.IntegerField('审计协议最大id', default=1)
    audit_log_max_id = models.IntegerField('审计设备log的最大id', default=1)
    strategy_apply_status = models.IntegerField(
        '当前策略的应用状态',
        choices=STRATEGY_APPLY_STATUS_CHOICES,
        default=STRATEGY_APPLY_STATUS_UN_APPLIED)
    apply_time = models.DateTimeField('策略下发时间', null=True)
    secret = models.CharField(max_length=64, null=True)
    template_name = models.CharField('设备应用的模板名', max_length=64, null=True,
                                     blank=True, default='未命名策略')
    log_template = models.ForeignKey(LogProcessTemplate, null=True,
                                     on_delete=models.SET_NULL,
                                     help_text='日志模板')
    log_status = models.BooleanField('日志开关', default=False,
                                     help_text='日志开关，默认关闭')

    class Meta:
        verbose_name = '设备'
        ordering = ('-id', 'registered_time')

    def __str__(self):
        return '{} {} {}'.format(self.id, self.get_type_display(), self.name)

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        # 要在添加安全设备时生成一个注册码
        sec_device_list = [Device.FIRE_WALL, Device.AUDITOR, Device.GATEKEEPER,
                           Device.IDS, Device.IPS, Device.SCANNER]

        if not self.register_code:
            if self.type in sec_device_list:
                self.register_code = random_string(REGISTER_CODE_LEN)

        if not self.mac:
            self.ip_mac_bond = False
        super(Device, self).save(force_insert, force_update, using,
                                 update_fields)


class DeviceMonitorSetting(models.Model):
    security_monitor_period = models.IntegerField('安全资产监控频率', default=10)
    communication_monitor_period = models.IntegerField('通信资产监控频率', default=10)
    server_monitor_period = models.IntegerField('主机资产监控频率', default=10)
    control_monitor_period = models.IntegerField('工控资产监控频率', default=10)

    security_cpu_alert_percent = models.IntegerField(
        '安全资产cpu使用率告警阈值',
        default=80,
        validators=[
            MinValueValidator(50),
            MaxValueValidator(
                100)])
    security_memory_alert_percent = models.IntegerField(
        '安全资产内存告警阈值',
        default=80,
        validators=[
            MinValueValidator(
                50),
            MaxValueValidator(
                100)])
    security_disk_alert_percent = models.IntegerField(
        '安全资产存储覆盖阈值', default=90,
        validators=[
            MinValueValidator(60),
            MaxValueValidator(
                100)])
    communication_cpu_alert_percent = models.IntegerField(
        '通信设备cpu使用率告警阈值',
        default=80,
        validators=[
            MinValueValidator(
                50),
            MaxValueValidator(
                100)])
    communication_memory_alert_percent = models.IntegerField(
        '通信设备内存告警阈值',
        default=80,
        validators=[
            MinValueValidator(
                50),
            MaxValueValidator(
                100)])
    communication_disk_alert_percent = models.IntegerField(
        '通信设备存储覆盖阈值',
        default=90,
        validators=[
            MinValueValidator(
                60),
            MaxValueValidator(
                100)])
    server_cpu_alert_percent = models.IntegerField(
        '主机设备cpu使用率告警阈值', default=80,
        validators=[
            MinValueValidator(50),
            MaxValueValidator(100)])
    server_memory_alert_percent = models.IntegerField(
        '主机设备内存告警阈值', default=80,
        validators=[
            MinValueValidator(50),
            MaxValueValidator(
                100)])
    server_disk_alert_percent = models.IntegerField(
        '主机设备存储覆盖阈值', default=90,
        validators=[
            MinValueValidator(60),
            MaxValueValidator(100)])
    control_cpu_alert_percent = models.IntegerField(
        '工控设备cpu使用率告警阈值',
        default=80,
        validators=[
            MinValueValidator(50),
            MaxValueValidator(100)])
    control_memory_alert_percent = models.IntegerField(
        '工控设备内存告警阈值', default=80,
        validators=[
            MinValueValidator(
                50),
            MaxValueValidator(
                100)])

    class Meta:
        verbose_name = '资产监控设置'

    def __str__(self):
        return '资产监控设置'

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        if DeviceMonitorSetting.objects.exists() and not self.pk:
            raise ValidationError(
                'There can be only one DeviceMonitorSetting instance')
        super(DeviceMonitorSetting, self).save(force_insert, force_update,
                                               using, update_fields)


class StrategyTemplate(models.Model):
    """
    策略模板表
    'name':             模板名，datetime
    'type':             模板类型，datetime
    'created_time':     创建时间，int
    'apply_time':       应用时间，datetime
    """

    name = models.CharField('模板名', max_length=32)
    type = models.IntegerField('模板类型', choices=Device.DEV_TEMP_TYPE_CHOICES)
    created_time = models.DateTimeField(auto_now_add=True)
    apply_time = models.DateTimeField('策略应用时间', null=True)

    def __str__(self):
        return '{} {}'.format(self.id, self.name)


class BaseStrategy(models.Model):
    """
    'type':             标识策略所属设备的（审计还是防火墙），非数据库字段
    'created_time':     b，datetime
    'edit_time':        编辑时间，datetime
    'device':           指向设备的外键，int
    'template':         指向模板的外键，datetime
    """

    type = None
    applicable = True  # 用于模板和设备策略相互转换时的标志位，True位可相互转换
    created_time = models.DateTimeField(auto_now_add=True, null=True)
    edit_time = models.DateTimeField(auto_now=True, null=True)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, null=True)
    template = models.ForeignKey(StrategyTemplate, on_delete=models.CASCADE,
                                 null=True)

    unique_attr_list = []  # some attr should be unique under a device or template

    @classmethod
    def dev_to_temp(cls, dev_id, temp_id, dev_type):

        strategy_sub_classes = get_device_applicable_strategy_subclasses(
            dev_type)
        for strategy_sub_class in strategy_sub_classes:
            strategies = strategy_sub_class.objects.filter(device_id=dev_id)
            result = [strategy_sub_class(
                **model_to_dict(item, exclude=MODEL_TO_DICT_EXCLUDE),
                template_id=temp_id)
                for item in strategies]
            strategy_sub_class.objects.bulk_create(result)

    @classmethod
    def temp_to_dev(cls, dev_id, temp_id, dev_type):

        strategy_sub_classes = get_device_applicable_strategy_subclasses(
            dev_type)
        for strategy_sub_class in strategy_sub_classes:
            strategies = strategy_sub_class.objects.filter(template_id=temp_id)
            result = [strategy_sub_class(
                **model_to_dict(item, exclude=MODEL_TO_DICT_EXCLUDE),
                device_id=dev_id)
                for item in strategies]
            strategy_sub_class.objects.bulk_create(result)

    @classmethod
    def temp_to_temp(cls, temp_id, new_temp_id, dev_type):

        strategy_sub_classes = get_device_applicable_strategy_subclasses(
            dev_type)
        for strategy_sub_class in strategy_sub_classes:
            strategies = strategy_sub_class.objects.filter(template_id=temp_id)
            result = [strategy_sub_class(
                **model_to_dict(item, exclude=MODEL_TO_DICT_EXCLUDE),
                template_id=new_temp_id)
                for item in strategies]
            strategy_sub_class.objects.bulk_create(result)

    @classmethod
    def del_dev_strategies(cls, dev_id, dev_type):
        strategy_sub_classes = get_device_strategy_subclasses(dev_type)
        for strategy_sub_class in strategy_sub_classes:
            strategy_sub_class.objects.filter(device_id=dev_id).delete()

    class Meta:
        abstract = True
        ordering = ('-created_time',)


class FirewallStrategy(BaseStrategy):
    """
    防火墙策略基类
    """
    type = Device.FIRE_WALL

    class Meta:
        abstract = True
        ordering = ('-created_time',)


class AuditorStrategy(BaseStrategy):
    """
    审计策略基类
    """

    type = Device.AUDITOR

    class Meta:
        abstract = True
        ordering = ('-created_time',)


class Log(models.Model):
    """
    日志基类
    'occurred_time':        发生时间, datetime
    'is_read':              是否已读, bool
    'read_time':            阅读时间, datetime
    'content':              日志内容, char
    """

    occurred_time = models.DateTimeField('发生时间', default=timezone.now,
                                         null=True)
    is_read = models.BooleanField('是否已读', default=False)
    read_at = models.DateTimeField('阅读时间', null=True)
    is_marked = models.BooleanField('是否标记', default=False)
    memo = models.CharField('备注', max_length=150, null=True, blank=True)
    content = models.CharField('内容', max_length=10000, blank=True, null=True)

    # content = models.TextField('内容', max_length=10000, blank=True, null=True)

    class Meta:
        abstract = True


class TerminalLog(Log):
    """
    终端日志基类
    'device':             指向终端设备的外键,int
    """

    device = models.ForeignKey(Device, on_delete=models.CASCADE)

    class Meta:
        abstract = True


class EventLog(models.Model):
    """
    存知识库的内容
    """

    # 审计事件
    AUDITOR_EVENT_BLACKLIST = 1
    AUDITOR_EVENT_ILLEGAL_IP = 2
    AUDITOR_EVENT_ILLEGAL_FLOW = 3
    AUDITOR_EVENT_MAC_NOT_MATCH = 4
    AUDITOR_EVENT_ICS = 5
    AUDITOR_EVENT_NO_TRAFFIC = 30
    # 防火墙事件
    FIREWALL_EVENT = 6

    # 系统事件
    LOGIN_LOGOUT = 7
    DEVICE_MANAGE = 8
    STRATEGT_MANAGE = 9
    ACCOUNT_MANAGE = 10

    # 资产事件
    ALL_ASSETS = 11
    MONITOR_ASSETS = 12

    TYPE_CHOICES = (
        # 审计事件
        (AUDITOR_EVENT_BLACKLIST, '黑名单告警'),
        (AUDITOR_EVENT_ILLEGAL_IP, '资产异常告警（陌生设备接入）'),
        (AUDITOR_EVENT_ILLEGAL_FLOW, '白名单告警（通讯行为异常）'),
        (AUDITOR_EVENT_MAC_NOT_MATCH, '资产异常告警(Mac地址冲突)'),
        (AUDITOR_EVENT_ICS, '白名单告警（通讯内容异常）'),
        (AUDITOR_EVENT_NO_TRAFFIC, '资产异常告警（设备离线）'),
        # 防火墙事件
        (FIREWALL_EVENT, '防火墙事件'),
        # 系统事件
        (DEVICE_MANAGE, '本机设置'),
        (STRATEGT_MANAGE, '策略管理'),
        (LOGIN_LOGOUT, '登录登出'),
        (ACCOUNT_MANAGE, '账号管理'),
        # 资产事件
        (ALL_ASSETS, '全部资产'),
        (MONITOR_ASSETS, '监控资产'),
    )

    EVENT_AUDITOR = 1
    EVENT_FIREWALL = 2
    EVENT_SYS = 3
    EVENT_ASSET = 4

    EVENT_CATEGORY_CHOICE = (
        (EVENT_AUDITOR, '审计事件'),
        (EVENT_FIREWALL, '防火墙事件'),
        (EVENT_SYS, '系统事件'),
        (EVENT_ASSET, '资产事件'),
    )

    LEVEL_CHOICE = (
        (0, '无'),
        (1, '低'),
        (2, '中'),
        (3, '高'),
    )

    name = models.CharField('事件名称', max_length=100)
    category = models.CharField('资产类别', max_length=20,
                                choices=EVENT_CATEGORY_CHOICE)
    type = models.IntegerField('资产类型', choices=TYPE_CHOICES)
    level = models.IntegerField('事件级别', choices=LEVEL_CHOICE, default=0)
    desc = models.CharField('事件特征描述', max_length=100, blank=True)
    log_desc = models.CharField('日志描述', max_length=100, blank=True)
    sec_desc = models.CharField('告警描述', max_length=100, blank=True)
    example_desc = models.CharField('举例子', max_length=100, blank=True)
    suggest_desc = models.CharField('处理建议', max_length=100, blank=True)

    class Meta:
        verbose_name = '安全事件库'
        # abstract = True

    def __str__(self):
        return '{} {}'.format(self.id, self.name)
