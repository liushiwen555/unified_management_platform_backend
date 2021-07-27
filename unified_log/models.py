from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.db.models import Q

from utils.constants import DEV_TEMP_TYPE_CHOICES, CATEGORY_CHOICE


SYSTEM_ADD = 1
MANUAL_ADD = 2
ADD_TYPE_CHOICES = (
    (SYSTEM_ADD, '系统内置'),
    (MANUAL_ADD, '用户添加')
)

LOG_KERNEL = 1
LOG_USER = 2
LOG_MAIL = 3
LOG_DAEMON = 4
LOG_AUTH = 5
LOG_SYSLOG = 6
LOG_LPR = 7
LOG_CRON = 8
LOG_AUDIT_ALARM = 9
LOG_NGINX = 10
LOG_POSTGRES = 11
LOG_AUTHPRIV = 12
LOG_FTP = 13
LOG_SWITCH_HUAWEI = 14
LOG_ROUTER_ASUS = 15
LOG_DATABASE_POSTGRESQL = 16
LOG_WINDOWS = 17

LOG_TYPE_CHOICES = (
    (LOG_KERNEL, '内核日志'),
    (LOG_USER, '用户日志'),
    (LOG_MAIL, '邮件日志'),
    (LOG_DAEMON, '后台任务日志'),
    (LOG_AUTH, '安全认证日志'),
    (LOG_SYSLOG, 'syslog日志'),
    (LOG_LPR, '打印机日志'),
    (LOG_CRON, '定时任务日志'),
    (LOG_AUDIT_ALARM, '审计告警日志'),
    (LOG_NGINX, 'Nginx日志'),
    (LOG_POSTGRES, 'Postgresql数据库日志'),
    (LOG_AUTHPRIV, '安全认证日志'),    # 和auth类似
    (LOG_FTP, 'FTP日志'),
    (LOG_SWITCH_HUAWEI, '华为交换机日志'),
    (LOG_ROUTER_ASUS, '华硕路由器日志'),
    (LOG_DATABASE_POSTGRESQL, 'postgres数据库日志'),
    (LOG_WINDOWS, 'Windows日志')
)


class LogProcessRule(models.Model):
    """
    日志处理规则表
    'name':             规则名称, char
    'category':         资产类别，和资产对应, int
    'type':             资产类型，和资产对应, int
    'brand':            厂商，char
    'hardware':         型号，char
    'status':           启用状态，bool
    'add':              添加方式，int
    'update_time':      更新时间，datetime
    'pattern':          解析规则，text
    'example':          日志样本，text
    'log_type':         日志类型，int
    'mark':             备注，char
    """

    CATEGORY_WINDOWS = 1
    CATEGORY_LINUX = 2
    CATEGORY_DOMESTIC = 3
    CATEGORY_CHOICES = (
        (CATEGORY_WINDOWS, 'Windows'),
        (CATEGORY_LINUX, 'Linux'),
        (CATEGORY_DOMESTIC, '国产平台'),
    )

    TYPE_WINDOWS = 1
    TYPE_LINUX = 2
    TYPE_DOMESTIC = 3

    TYPE_CHOICES = (
        (TYPE_WINDOWS, 'Windows'),
        (TYPE_LINUX, 'Linux'),
        (TYPE_DOMESTIC, '国产平台'),
    )

    name = models.CharField('规则名称', max_length=16, help_text='规则名称')
    category = models.IntegerField('系统类别', choices=CATEGORY_CHOICES,
                                   help_text='系统类别')
    type = models.IntegerField('系统类型', choices=TYPE_CHOICES,
                               help_text='系统类型')
    brand = models.CharField('厂商', max_length=10, blank=True, null=True,
                             help_text='厂商')
    hardware = models.CharField('型号', max_length=10, blank=True, null=True,
                                help_text='型号')
    add = models.IntegerField('添加方式', choices=ADD_TYPE_CHOICES,
                              default=SYSTEM_ADD, help_text='添加方式，默认是系统内置')
    update_time = models.DateTimeField('更新时间', auto_now=True,
                                       help_text='规则更新时间')
    pattern = models.TextField('匹配规则', help_text='匹配规则')
    example = models.TextField('日志样本', blank=True, null=True,
                               help_text='日志样本')
    log_type = models.IntegerField('日志类型', choices=LOG_TYPE_CHOICES,
                                   help_text='自定义的日志类型，比如auth，nginx，mysql等')
    mark = models.CharField('备注', max_length=100, blank=True, null=True,
                            help_text='备注')

    class Meta:
        verbose_name = '日志解析规则'
        ordering = ('-id',)
        unique_together = ('name', 'category', 'type')

    def template_count(self) -> int:
        """
        统计启用规则的模板的数量，因为模板里面可以启用多种规则，需要用 or 查询，避免重复
        :return: 启用该日志的模板数
        """
        return LogProcessTemplate.objects.filter(
            Q(kern=self) | Q(user=self) | Q(mail=self) | Q(daemon=self)
            | Q(auth=self) | Q(syslog=self) | Q(lpr=self) | Q(cron=self)
            | Q(local0=self) | Q(local1=self) | Q(local2=self) | Q(local3=self)
            | Q(local4=self) | Q(local5=self) | Q(local6=self) | Q(local7=self)
        ).count()

    def __str__(self) -> str:
        return f'日志规则: {self.name}'


class LogProcessTemplate(models.Model):
    """
    日志处理规则表
    'name':             规则名称, char
    'category':         资产类别，和资产对应, int
    'type':             资产类型，和资产对应, int
    'brand':            厂商，char
    'hardware':         型号，char
    'status':           启用状态，bool
    'add':              添加方式，int
    'update_time':      更新时间，datetime
    'pattern':          解析规则，text
    'example':          日志样本，text
    'mark':             备注，char
    'kern':             内核关联日志规则, LogProcessRule
    'user':             用户关联日志规则, LogProcessRule
    'mail':             邮件关联日志规则, LogProcessRule
    'daemon':           后台程序关联日志规则, LogProcessRule
    'auth':             安全认证关联日志规则, LogProcessRule
    'syslog':           syslog关联日志规则, LogProcessRule
    'lpr':              打印机关联日志规则, LogProcessRule
    'cron':             定时任务关联日志规则, LogProcessRule
    'local0':           自定义日志关联日志规则, LogProcessRule
    'local1':           自定义日志关联规则, LogProcessRule
    'local2':           自定义日志关联规则, LogProcessRule
    'local3':           自定义日志关联规则, LogProcessRule
    'local4':           自定义日志关联规则, LogProcessRule
    'local5':           自定义日志关联规则, LogProcessRule
    'local6':           自定义日志关联规则, LogProcessRule
    'local7':           自定义日志关联规则, LogProcessRule
    """
    name = models.CharField('规则名称', max_length=16, help_text='规则名称')
    category = models.IntegerField('资产类别', choices=CATEGORY_CHOICE,
                                   help_text='资产类别')
    type = models.IntegerField('资产类型', choices=DEV_TEMP_TYPE_CHOICES,
                               help_text='资产类型')
    brand = models.CharField('厂商', max_length=10, blank=True, null=True,
                             help_text='厂商')
    hardware = models.CharField('型号', max_length=10, blank=True, null=True,
                                help_text='型号')
    add = models.IntegerField('添加方式', choices=ADD_TYPE_CHOICES,
                              default=SYSTEM_ADD, help_text='添加方式')
    update_time = models.DateTimeField('更新时间', auto_now=True,
                                       help_text='更新时间')
    mark = models.CharField('备注', max_length=100, blank=True, null=True,
                            help_text='备注')

    """
    facility和规则关联
    Rsyslog facility的定义：https://en.wikipedia.org/wiki/Syslog#Facility
    """
    kern = models.ForeignKey(LogProcessRule, related_name='kern_temp',
                             null=True, on_delete=models.SET_NULL)
    user = models.ForeignKey(LogProcessRule, related_name='user_temp',
                             null=True, on_delete=models.SET_NULL)
    mail = models.ForeignKey(LogProcessRule, related_name='mail_temp',
                             null=True, on_delete=models.SET_NULL)
    daemon = models.ForeignKey(LogProcessRule, related_name='daemon_temp',
                               null=True, on_delete=models.SET_NULL)
    auth = models.ForeignKey(LogProcessRule, related_name='auth_temp',
                             null=True, on_delete=models.SET_NULL)
    syslog = models.ForeignKey(LogProcessRule, related_name='syslog_temp',
                               null=True, on_delete=models.SET_NULL)
    lpr = models.ForeignKey(LogProcessRule, related_name='lpr_temp',
                            null=True, on_delete=models.SET_NULL)
    cron = models.ForeignKey(LogProcessRule, related_name='cron_temp',
                             null=True, on_delete=models.SET_NULL)
    ftp = models.ForeignKey(LogProcessRule, related_name='ftp_temp',
                            null=True, on_delete=models.SET_NULL)
    authpriv = models.ForeignKey(LogProcessRule, related_name='authpriv_temp',
                                 null=True, on_delete=models.SET_NULL)
    local0 = models.ForeignKey(LogProcessRule, related_name='local0_temp',
                               null=True, on_delete=models.SET_NULL)
    local1 = models.ForeignKey(LogProcessRule, related_name='local1_temp',
                               null=True, on_delete=models.SET_NULL)
    local2 = models.ForeignKey(LogProcessRule, related_name='local2_temp',
                               null=True, on_delete=models.SET_NULL)
    local3 = models.ForeignKey(LogProcessRule, related_name='local3_temp',
                               null=True, on_delete=models.SET_NULL)
    local4 = models.ForeignKey(LogProcessRule, related_name='local4_temp',
                               null=True, on_delete=models.SET_NULL)
    local5 = models.ForeignKey(LogProcessRule, related_name='local5_temp',
                               null=True, on_delete=models.SET_NULL)
    local6 = models.ForeignKey(LogProcessRule, related_name='local6_temp',
                               null=True, on_delete=models.SET_NULL)
    local7 = models.ForeignKey(LogProcessRule, related_name='local7_temp',
                               null=True, on_delete=models.SET_NULL)

    class Meta:
        verbose_name = '日志解析模版'
        ordering = ('-id', )
        unique_together = ('name', 'category', 'type')

    def __str__(self):
        return f'日志解析模板: {self.name}'


class LogStatistic(models.Model):
    device = models.OneToOneField('base_app.Device', on_delete=models.CASCADE)
    today = models.PositiveIntegerField(help_text='本日日志', default=0)
    total = models.PositiveIntegerField(help_text='累计日志', default=0)
    update_time = models.DateTimeField(help_text='上次采集时间', null=True)


class AbstractRules(object):
    facilities = ['local0', 'local1', 'local2', 'local3', 'local4', 'local5',
                  'local6', 'local7', 'kern', 'user', 'mail', 'daemon',
                  'auth', 'syslog', 'lpr', 'cron', 'ftp', 'authpriv']

    def __init__(self, instance: LogProcessTemplate):
        for i in self.facilities:
            setattr(self, i, getattr(instance, i))


class AbstractRule(object):
    def __init__(self, id: int):
        self.id = id
