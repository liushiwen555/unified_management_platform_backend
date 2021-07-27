from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models

from base_app.models import BaseStrategy, TerminalLog, Device, FirewallStrategy
from utils.core.mixins import UniqueAttrMixin, UniqueModelMixin
from utils.validators import MAC_VALIDATOR, IPV4_VALIDATOR

User = get_user_model()

ACTION_DENY = 0
ACTION_PERMIT = 1
ACTION_CHOICES = (
    (ACTION_DENY, '拒绝'),
    (ACTION_PERMIT, '允许'),
)

STATUS_DISABLE = 0
STATUS_ENABLE = 1
STATUS_CHOICES = (
    (STATUS_DISABLE, '关闭'),
    (STATUS_ENABLE, '开启'),
)

LOGGING_OFF = 0
LOGGING_ON = 1
LOGGING_CHOICES = (
    (LOGGING_OFF, '关闭'),
    (LOGGING_ON, '开启'),
)


class ConfStrategy(UniqueModelMixin, FirewallStrategy):
    """
    策略设置表
    'id':               记录id,int
    'run_mode':         运行模式, int
    'default_filter':   默认禁止, int
    'DPI':              深度检测, int
    """
    RUN_MODE_TEST = 0
    RUN_MODE_WORKING = 1
    RUN_MODE_CHOICES = (
        (RUN_MODE_TEST, '测试模式'),
        (RUN_MODE_WORKING, '工作模式'),
    )

    DEFAULT_FILTER_ON = 0
    DEFAULT_FILTER_OFF = 1
    DEFAULT_FILTER_CHOICES = (
        (DEFAULT_FILTER_ON, '开启'),
        (DEFAULT_FILTER_OFF, '关闭'),
    )

    DPI_ON = 1
    DPI_OFF = 0
    DPI_CHOICES = (
        (DPI_ON, '开启'),
        (DPI_OFF, '关闭'),
    )

    run_mode = models.IntegerField('运行模式', choices=RUN_MODE_CHOICES)
    default_filter = models.IntegerField('默认禁止', choices=DEFAULT_FILTER_CHOICES)
    DPI = models.IntegerField('深度检测', choices=DPI_CHOICES)


class BaseFirewallStrategy(UniqueAttrMixin, FirewallStrategy):
    """
    基础防火墙策略表
    'rule_id':          规则ID,int
    'rule_name':        规则名称,char
    'src_ip':           源ip,ip
    'dst_ip':           目的ip,ip
    'src_port':         源端口,int
    'dst_port':         目的端口,int
    'protocol':         协议,char
    'action':           动作,int
    'status':           状态,int
    'logging':          记录日志,int
    """
    rule_id = models.IntegerField('规则ID', validators=[MinValueValidator(1), MaxValueValidator(1024)])
    rule_name = models.CharField('规则名称', max_length=64)
    src_ip = models.CharField('源ip', max_length=64, validators=[IPV4_VALIDATOR])
    dst_ip = models.CharField('目的ip', max_length=64, validators=[IPV4_VALIDATOR])
    src_port = models.IntegerField('源端口', null=True, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    dst_port = models.IntegerField('目的端口', null=True, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    protocol = models.CharField('协议', max_length=32, blank=True, null=True)
    action = models.IntegerField('动作', choices=ACTION_CHOICES)
    status = models.IntegerField('状态', choices=STATUS_CHOICES)
    logging = models.IntegerField('记录日志', choices=LOGGING_CHOICES)

    unique_attr_list = ['rule_id']


class FirewallWhiteListStrategy(UniqueAttrMixin, FirewallStrategy):
    """
    防火墙白名单策略表
    'rule_id':          规则ID,int
    'rule_name':        规则名称,char
    'src_ip':           源ip,ip
    'dst_ip':           目的ip,ip
    'src_port':         源端口,int
    'dst_port':         目的端口,int
    'protocol':         协议,char
    'action':           动作,int
    'status':           状态,int
    'logging':          记录日志,int
    """
    rule_id = models.IntegerField('规则ID')
    rule_name = models.CharField('规则名称', max_length=64)
    src_ip = models.CharField('源ip', max_length=64, validators=[IPV4_VALIDATOR])
    dst_ip = models.CharField('目的ip', max_length=64, validators=[IPV4_VALIDATOR])
    src_port = models.IntegerField('源端口', null=True, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    dst_port = models.IntegerField('目的端口', null=True, validators=[MinValueValidator(1), MaxValueValidator(65535)])
    protocol = models.CharField('协议', max_length=32, blank=True, null=True)
    action = models.IntegerField('动作', choices=ACTION_CHOICES, default=ACTION_PERMIT)
    status = models.IntegerField('状态', choices=STATUS_CHOICES, default=STATUS_DISABLE)
    logging = models.IntegerField('记录日志', choices=LOGGING_CHOICES, default=LOGGING_OFF)

    unique_attr_list = ['rule_id']


class FirewallLearnedWhiteListStrategy(FirewallStrategy):

    """
    防火墙自学习白名单策略表
    'sid':              规则ID,int
    'fields':           操作码,char
    'body':             预留，暂未用到,char
    'filter_fields':    预留，暂未用到,char
    'level':            风险等级,int
    'rule_name':        规则名称,char
    'src_ip':           源ip,ip
    'dst_ip':           目的ip,ip
    'src_mac':          源mac地址,char
    'dst_mac':          目的mac地址,char
    'proto':            协议,char
    'tmp_action':       临时动作,int
    'action':           动作类型,int
    'proto_name':       协议名称,char
    'status':           状态,int
    """

    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3

    LEVEL_CHOICE = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    LEARNED_WHITELIST_ACTION_PASS = 0
    LEARNED_WHITELIST_ACTION_WARNING = 1
    LEARNED_WHITELIST_ACTION_DROP = 2
    LEARNED_WHITELIST_ACTION_BLOCK = 3

    LEARNED_WHITELIST_ACTION_CHOICES = (
        (LEARNED_WHITELIST_ACTION_PASS, '通过'),
        (LEARNED_WHITELIST_ACTION_WARNING, '告警'),
        (LEARNED_WHITELIST_ACTION_DROP, '丢弃'),
        (LEARNED_WHITELIST_ACTION_BLOCK, '阻断'),
    )

    applicable = False
    sid = models.IntegerField('规则ID')
    fields = models.CharField('操作码', max_length=1000)
    body = models.CharField(null=True, max_length=1000)
    filter_fields = models.CharField(null=True, max_length=1000)
    level = models.IntegerField('风险等级', choices=LEVEL_CHOICE)
    rule_name = models.CharField('规则名称', max_length=64)
    src_ip = models.GenericIPAddressField('源ip', blank=True, null=True)
    dst_ip = models.GenericIPAddressField('目的ip', blank=True, null=True)
    src_mac = models.CharField('源mac地址', validators=[MAC_VALIDATOR], max_length=32, null=True, blank=True)
    dst_mac = models.CharField('目标mac地址', validators=[MAC_VALIDATOR], max_length=32, null=True, blank=True)
    proto = models.CharField('协议', null=True, max_length=32)
    tmp_action = models.IntegerField('临时动作', choices=LEARNED_WHITELIST_ACTION_CHOICES, null=True)
    action = models.IntegerField('动作类型', choices=LEARNED_WHITELIST_ACTION_CHOICES)
    proto_name = models.CharField('协议名称', max_length=32)
    status = models.IntegerField('状态', choices=STATUS_CHOICES, default=STATUS_DISABLE)


class IndustryProtocolDefaultConfStrategy(UniqueModelMixin, FirewallStrategy):

    """
    默认设置表
    'OPC_default_action':           OPC-DA默认动作, int
    'modbus_default_action':        modbus默认动作, int
    """
    OPC_default_action = models.IntegerField('OPC-DA默认动作', choices=STATUS_CHOICES)
    modbus_default_action = models.IntegerField('modbus默认动作', choices=STATUS_CHOICES)


class IndustryProtocolOPCStrategy(UniqueModelMixin, FirewallStrategy):
    """
    OPC读写表
    'is_read_open':         读取开关,bool
    'read_action':          读取事件处理,int
    'is_write_open':        写入开关,bool
    'write_action':         写入事件处理,int
    """
    READ_WRITE_ACTION_PASS = 1
    READ_WRITE_ACTION_WARNING = 2
    READ_WRITE_ACTION_DROP = 3
    READ_WRITE_ACTION_BLOCK = 4

    READ_WRITE_ACTION_CHOICES = (
        (READ_WRITE_ACTION_PASS, '通过'),
        (READ_WRITE_ACTION_WARNING, '告警'),
        (READ_WRITE_ACTION_DROP, '丢弃'),
        (READ_WRITE_ACTION_BLOCK, '阻断'),
    )
    is_read_open = models.BooleanField('读取开关', default=False)
    read_action = models.IntegerField('读取事件处理', choices=READ_WRITE_ACTION_CHOICES, default=READ_WRITE_ACTION_PASS)
    is_write_open = models.BooleanField('写入开关', default=False)
    write_action = models.IntegerField('写入事件处理', choices=READ_WRITE_ACTION_CHOICES, default=READ_WRITE_ACTION_PASS)


class IndustryProtocolModbusStrategy(UniqueAttrMixin, FirewallStrategy):
    """
    防火墙modbus策略表
    'rule_id':              规则ID,int
    'rule_name':            规则名称,char
    'func_code':            功能码,char
    'reg_start':            开始地址,char
    'reg_end':              结束地址,char
    'reg_value':            寄存器值,char
    'length':               长度,int
    'action':               动作,int
    'logging':              记录日志,int
    'status':               状态,int
    """

    FUNC_CODE_CHOICE = (
        (1, '读保持线圈状态'),
        (2, '读输入线圈状态'),
        (3, '读保持寄存器'),
        (4, '读输入寄存器'),
        (5, '写单个线圈'),
        (6, '写单个寄存器'),
        (7, '读取异常状态'),
        (8, '回路诊断'),
        (9, '编程_only_484'),
        (10, '控询_only_484'),
        (11, '读取事件计数'),
        (12, '读取通信事件记录'),
        (13, '编程_184_384_484_584'),
        (14, '探询_184_384_484_584'),
        (15, '写多个线圈'),
        (16, '写多个寄存器'),
        (17, '报告从机标识'),
        (19, '重置通信链路'),
        (20, '读取通用参数(584L)'),
        (21, '写入通用参数(584L)'),
        (0, '未知'),
    )

    rule_id = models.IntegerField('规则ID')
    rule_name = models.CharField('规则名称', max_length=64)
    func_code = models.IntegerField('功能码', choices=FUNC_CODE_CHOICE, default=0)

    reg_start = models.IntegerField('开始地址', )
    reg_end = models.IntegerField('结束地址',)
    reg_value = models.IntegerField('寄存器值')
    length = models.IntegerField('长度')
    action = models.IntegerField('动作', choices=ACTION_CHOICES)
    logging = models.IntegerField('记录日志', choices=LOGGING_CHOICES, default=LOGGING_OFF)
    status = models.IntegerField('状态', choices=STATUS_CHOICES, default=STATUS_DISABLE)

    unique_attr_list = ['rule_id']


class IndustryProtocolS7Strategy(UniqueAttrMixin, FirewallStrategy):
    """
    S7协议策略表
    'rule_id':              规则ID,int
    'rule_name':            规则名称,char
    'func_type':            Function type,char
    'pdu_type':             pdu type,char
    'action':               动作,int
    'status':               状态,int
    """
    rule_id = models.IntegerField('规则ID')
    rule_name = models.CharField('规则名称', max_length=64)
    func_type = models.CharField('Function type', max_length=64)
    pdu_type = models.CharField('pdu type', max_length=64)
    action = models.IntegerField('动作', choices=ACTION_CHOICES)
    status = models.IntegerField('状态', choices=STATUS_CHOICES)

    unique_attr_list = ['rule_id']


class FirewallBlackList(models.Model):
    """
    黑名单库（防火墙设备和模板生成时的黑名单策略来源）
    黑名单列表页信息：
    'id':                   记录id，主键
    'name':                 名称, char
    'publish_date':         发布日期, date
    'action':               动作, int 1告警 2丢弃 3阻断
    'feature_code':         规则sid, char
    'level':                风险等级, int
    'status':               激活状态, int 0关闭 1开启
    """

    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3

    LEVEL_CHOICE = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    EVENT_PROCESS_PASS = 0
    EVENT_PROCESS_WARNING = 1
    EVENT_PROCESS_DROP = 2
    EVENT_PROCESS_BLOCK = 3

    EVENT_PROCESS_CHOICES = (
        (EVENT_PROCESS_PASS, '通过'),
        (EVENT_PROCESS_WARNING, '告警'),
        (EVENT_PROCESS_DROP, '丢弃'),
        (EVENT_PROCESS_BLOCK, '阻断'),
    )

    name = models.CharField('漏洞名称', max_length=1000)
    publish_date = models.DateField('发布时间')
    action = models.IntegerField('事件处理', choices=EVENT_PROCESS_CHOICES, default=EVENT_PROCESS_PASS)
    feature_code = models.CharField('特征编号', max_length=20)
    level = models.IntegerField('特征风险等级', choices=LEVEL_CHOICE)
    status = models.IntegerField('启用状态', choices=STATUS_CHOICES, default=STATUS_DISABLE)

    class Meta:
        verbose_name = '黑名单'
        ordering = ['id']

    def __str__(self):
        return '{} {}'.format(self.feature_code, self.name)


class FirewallBlackListStrategy(FirewallStrategy):
    """
    防火墙黑名单表：
    'id':                   记录id，主键
    'name':                 名称, char
    'publish_date':         发布日期, date
    'action':               动作, int 1告警 2丢弃 3阻断
    'feature_code':         规则sid, char
    'level':                风险等级, int
    'status':               激活状态, int 0关闭 1开启
    """
    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3

    LEVEL_CHOICE = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    EVENT_PROCESS_PASS = 0
    EVENT_PROCESS_WARNING = 1
    EVENT_PROCESS_DROP = 2
    EVENT_PROCESS_BLOCK = 3

    EVENT_PROCESS_CHOICES = (
        (EVENT_PROCESS_PASS, '通过'),
        (EVENT_PROCESS_WARNING, '告警'),
        (EVENT_PROCESS_DROP, '丢弃'),
        (EVENT_PROCESS_BLOCK, '阻断'),
    )

    name = models.CharField('漏洞名称', max_length=1000, null=True, blank=True)
    cve = models.CharField('CVE编号', max_length=20,null=True, blank=True)
    category = models.CharField('类型', max_length=20, null=True, blank=True)
    # loophole_src = models.CharField('漏洞来源', max_length=1000)
    publish_date = models.DateField('发布时间')
    # triggered_dev = models.CharField('触发设备', max_length=1000)
    # rule_src = models.CharField('规则来源', max_length=1000)
    action = models.IntegerField('事件处理', choices=EVENT_PROCESS_CHOICES, default=EVENT_PROCESS_PASS)
    # effected_vendor = models.CharField('受影响厂商', max_length=1000)
    requirement = models.CharField('攻击条件', max_length=100,null=True, blank=True)
    description = models.CharField('规则描述', max_length=10000,null=True, blank=True)
    vulnerable = models.CharField('影响范围', max_length=10000,null=True, blank=True) # 这个应该没有
    effect = models.CharField('威胁', max_length=100,null=True, blank=True)   #这个应该没有
    suggest = models.CharField('建议', max_length=10000, null=True, blank=True)    #这个应该没有
    # feature_name = models.CharField('特征名称', max_length=1000)
    feature_code = models.CharField('特征编号', max_length=20, null=True, blank=True)
    level = models.IntegerField('特征风险等级', choices=LEVEL_CHOICE)
    # feature_priority = models.CharField('特征优先级', max_length=1000)
    status = models.IntegerField('启用状态', choices=STATUS_CHOICES, default=STATUS_DISABLE)


class FirewallIPMACBondStrategy(UniqueAttrMixin, FirewallStrategy):
    """
    IP Mac绑定策略
    'device_name':          设备名称,char
    'ip':                   ip,ip
    'mac':                  mac,char
    'status':               启用状态,int
    'action':               动作,int
    """
    ACTION_PASS = 0
    ACTION_WARNING = 1
    ACTION_DROP = 2
    ACTION_BLOCK = 3

    ACTION_CHOICES = (
        (ACTION_PASS, '通过'),
        (ACTION_WARNING, '告警'),
        (ACTION_DROP, '丢弃'),
        (ACTION_BLOCK, '阻断'),
    )
    device_name = models.CharField('设备名称', max_length=64)
    ip = models.GenericIPAddressField('ip')
    mac = models.CharField('mac', validators=[MAC_VALIDATOR], max_length=32)
    status = models.IntegerField('启用状态', choices=STATUS_CHOICES, default=STATUS_DISABLE)
    action = models.IntegerField('动作', choices=ACTION_CHOICES, default=ACTION_PASS)

    unique_attr_list = ['ip', 'mac']

    class Meta:
        ordering = ('-created_time',)


class FirewallIPMACUnknownDeviceActionStrategy(UniqueModelMixin, FirewallStrategy):
    """
    防火墙IP Mac绑定，未知设备动作表
    'action':           动作,int
    """
    ACTION_PASS = 0
    ACTION_WARNING = 1
    ACTION_DROP = 2
    ACTION_BLOCK = 3

    ACTION_CHOICES = (
        (ACTION_PASS, '通过'),
        (ACTION_WARNING, '告警'),
        (ACTION_DROP, '丢弃'),
        (ACTION_BLOCK, '阻断'),
    )

    action = models.IntegerField('动作', choices=ACTION_CHOICES, default=ACTION_PASS)


class FirewallSecEvent(TerminalLog):
    """
    防火墙安全事件表
    'src_ip':               源地址,ip
    'dst_ip':               目的地址,ip
    'src_mac':              源mac地址,char
    'dst_mac':              目标mac地址,char
    'protocol':             协议,char
    'app_layer_protocol':   应用层协议,char
    'packet_length':        包长度,int
    'signature_msg':        备注,char
    'matched_key':          规则项,char
    'protocol_detail':      协议细节,char
    'packet':               原始数据包内容,char
    'alert_type':           告警类型,int
    'status':               读取状态,int
    'level':                风险等级,int
    'action':               动过,int
    """
    STATUS_UNREAD = 0
    STATUS_READ = 1

    READ_STATUS_CHOICES = (
        (STATUS_READ, '已读'),
        (STATUS_UNREAD, '未读'),
    )

    LEVEL_LOW = 1
    LEVEL_MEDIUM = 2
    LEVEL_HIGH = 3

    LEVEL_CHOICES = (
        (LEVEL_LOW, '低'),
        (LEVEL_MEDIUM, '中'),
        (LEVEL_HIGH, '高'),
    )

    ACTION_PASS = 0
    ACTION_WARNING = 1
    ACTION_DROP = 2
    ACTION_BLOCK = 3

    ACTION_CHOICES = (
        (ACTION_PASS, '通过'),
        (ACTION_WARNING, '告警'),
        (ACTION_DROP, '丢弃'),
        (ACTION_BLOCK, '阻断'),
    )

    src_ip = models.GenericIPAddressField('源地址', blank=True, null=True)
    dst_ip = models.GenericIPAddressField('目的地址', blank=True, null=True)
    src_mac = models.CharField('源mac地址', validators=[MAC_VALIDATOR], max_length=32, blank=True, null=True)
    dst_mac = models.CharField('目标mac地址', validators=[MAC_VALIDATOR], max_length=32, blank=True, null=True)
    protocol = models.CharField('协议', max_length=32, blank=True, null=True)
    app_layer_protocol = models.CharField('应用层协议', max_length=32, blank=True, null=True)
    packet_length = models.IntegerField('包长度')
    signature_msg = models.CharField('备注', max_length=1024, blank=True, null=True)
    matched_key = models.CharField('规则项', max_length=1024, blank=True, null=True)
    protocol_detail = models.CharField('协议细节', max_length=1024, blank=True, null=True)
    packet = models.TextField('原始数据包内容', max_length=1024, blank=True, null=True)
    alert_type = models.IntegerField('告警类型', default=0)
    status = models.IntegerField('读取状态', choices=STATUS_CHOICES)
    level = models.IntegerField('风险等级', choices=LEVEL_CHOICES)
    action = models.IntegerField('动作', choices=ACTION_CHOICES)

    class Meta:
        verbose_name = '防火墙安全事件'
        ordering = ['-occurred_time']


class FirewallSysEvent(TerminalLog):
    """
    防火墙系统事件日志表
    'level':            事件等级,int
    'type':             事件类型,int
    'status':           事件状态,int
    """
    LEVEL_MESSAGE = 0
    LEVEL_WARNING = 1
    LEVEL_MESSAGE_AND_WARNING = 3

    LEVEL_CHOICES = (
        (LEVEL_MESSAGE, '信息'),
        (LEVEL_WARNING, '告警'),
        (LEVEL_MESSAGE_AND_WARNING, '信息和告警'),
    )

    STATUS_UNREAD = 0
    STATUS_READ = 1

    READ_STATUS_CHOICES = (
        (STATUS_READ, '已读'),
        (STATUS_UNREAD, '未读'),
    )

    EVENT_TYPE_DEVICE_STATUS = 0
    EVENT_TYPE_INTERFACE_STATUS = 1
    EVENT_TYPE_DATA_COLLECT = 10
    EVENT_TYPE_DISK_CLEAN = 11
    EVENT_TYPE_WHITELIST = 12
    EVENT_TYPE_BLACKLIST = 13
    EVENT_TYPE_IP_MAC = 14
    EVENT_TYPE_NO_FLOW = 15
    EVENT_TYPE_BASE_FIREWALL = 19
    EVENT_TYPE_CUSTOM_WHITELIST = 20
    EVENT_TYPE_SESSION_MANAGEMENT = 21
    EVENT_TYPE_INDUSTRY_PROTOCOL = 22

    EVENT_TYPE_CHOICES = (
        (EVENT_TYPE_DEVICE_STATUS, '设备状态'),
        (EVENT_TYPE_INTERFACE_STATUS, '接口状态'),
        (EVENT_TYPE_DATA_COLLECT, '数据采集'),
        (EVENT_TYPE_DISK_CLEAN, '磁盘清理'),
        (EVENT_TYPE_WHITELIST, '白名单'),
        (EVENT_TYPE_BLACKLIST, '黑名单'),
        (EVENT_TYPE_IP_MAC, 'IP MAC'),
        (EVENT_TYPE_NO_FLOW, '无流量监测'),
        (EVENT_TYPE_BASE_FIREWALL, '基础防火墙'),
        (EVENT_TYPE_CUSTOM_WHITELIST, '自定义白名单'),
        (EVENT_TYPE_SESSION_MANAGEMENT, '连接管理'),
        (EVENT_TYPE_INDUSTRY_PROTOCOL, '工业协议'),
    )
    level = models.IntegerField('事件等级', choices=LEVEL_CHOICES)
    type = models.IntegerField('事件类型', choices=EVENT_TYPE_CHOICES)
    status = models.IntegerField('事件状态', choices=READ_STATUS_CHOICES)

    class Meta:
        verbose_name = '防火墙系统事件'
        ordering = ['-occurred_time']