from typing import List, Type

from django.db import models
from django.contrib.postgres.fields import ArrayField, JSONField
from django.core.serializers.json import DjangoJSONEncoder
from rest_framework.exceptions import ValidationError


class CleanRegister(object):
    """
    将需要定时清理的模型注册到这里，然后在定时任务里取出注册的模型并执行清理任务
    """
    def __init__(self):
        self._register: List[Type[models.Model]] = []

    def register(self, clazz):
        self._register.append(clazz)
        return clazz

    def get_all(self):
        return self._register


clean_register = CleanRegister()


@clean_register.register
class MainView(models.Model):
    alert_count = models.IntegerField(help_text='累计的安全事件与安全威胁总量')
    un_resolved = models.IntegerField(help_text='未处理的安全事件与安全威胁总量')
    log_count = models.IntegerField(help_text='累计获取的日志总量')
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-主视图'
        ordering = ('-id',)

    def __str__(self):
        return 'id:{},alert_count:{},un_resolved:{},log_count:{},' \
               'update_time:{}'.format(self.id, self.alert_count,
                                       self.un_resolved, self.log_count,
                                       self.update_time)


@clean_register.register
class AssetsCenter(models.Model):
    all = models.IntegerField(help_text='全部资产')
    security = models.IntegerField(help_text='安全资产')
    server = models.IntegerField(help_text='主机资产')
    network = models.IntegerField(help_text='网络资产')
    control = models.IntegerField(help_text='工控资产')
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-资产中心'
        ordering = ('-id',)


@clean_register.register
class MonitorCenter(models.Model):
    monitor_count = models.IntegerField(help_text='监控资产')
    monitor_percent = models.IntegerField(help_text='性能监控比率')
    online_percent = models.IntegerField(help_text='在线比率')
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-资产中心'
        ordering = ('-id',)


@clean_register.register
class LogCenter(models.Model):
    collect = models.IntegerField(help_text='采集日志')
    parsed = models.IntegerField(help_text='解析日志')
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-主视图-日志中心'
        ordering = ('-id',)


@clean_register.register
class LogStatistic(models.Model):
    """
    日志中心日志统计
    """
    total = models.PositiveIntegerField(help_text='日志总量')
    local = models.PositiveIntegerField(help_text='本地日志')
    collect = models.PositiveIntegerField(help_text='采集日志')
    local_current = models.PositiveIntegerField(help_text='当天目前本地日志量')
    collect_current = models.PositiveIntegerField(help_text='当天目前采集日志量')
    local_hour = models.PositiveIntegerField(help_text='当前小时本地日志量')
    collect_hour = models.PositiveIntegerField(help_text='当前小时采集日志量')
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-日志中心'
        ordering = ('-id', )


@clean_register.register
class LogStatisticDay(models.Model):
    """
    日志中心按天统计日志
    """
    local_today = models.PositiveIntegerField(help_text='当天本地日志量')
    collect_today = models.PositiveIntegerField(help_text='当天采集日志量')
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-日志中心按天统计'
        ordering = ('-id', )


@clean_register.register
class LogDstIPTopFive(models.Model):
    """
    采集日志目的IP TOP5
    """
    ip = ArrayField(models.CharField(max_length=30), size=5)
    today = ArrayField(models.PositiveIntegerField(), size=5)
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-日志中心目的IP top five'


class LogDstIP(object):
    def __init__(self, ip, today, percent):
        self.ip = ip
        self.today = today
        self.percent = percent


@clean_register.register
class LogCategoryDistribution(models.Model):
    """
    采集日志按照资产类别统计
    """
    security = models.PositiveIntegerField(help_text='安全资产', default=0)
    server = models.PositiveIntegerField(help_text='主机资产', default=0)
    network = models.PositiveIntegerField(help_text='网络资产', default=0)
    control = models.PositiveIntegerField(help_text='工控资产', default=0)
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-日志中心-采集日志按照分类统计'
        ordering = ('-id', )


@clean_register.register
class LogPortDistribution(models.Model):
    ports = ArrayField(models.CharField(help_text='端口', max_length=10), size=10)
    total = ArrayField(models.IntegerField(help_text='日志数'), size=10)
    update_time = models.DateTimeField(help_text='更新时间')

    class Meta:
        verbose_name = '运营态势-日志中心-端口分布'
        ordering = ('-id', )


@clean_register.register
class SystemRunning(models.Model):
    cpu = models.IntegerField('CPU利用率')
    memory = models.IntegerField('内存利用率')
    disk = models.IntegerField('硬盘利用率')
    network = JSONField('网口流速', encoder=DjangoJSONEncoder, default=dict)
    update_time = models.DateTimeField(help_text='更新时间', auto_now_add=True)

    class Meta:
        verbose_name = '运行中心-设备运行状态'
        ordering = ('-id', )


class IPDistribution(models.Model):
    """
    资产中心——IP分布情况，只存昨天的数据，而且只存一份，所以也不用在删除历史数据
    """
    ips = JSONField(encoder=DjangoJSONEncoder, default=dict)
    update_time = models.DateTimeField(help_text='更新时间', auto_now=True)

    class Meta:
        verbose_name = 'IP使用情况'

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        if IPDistribution.objects.exists() and not self.pk:
            # 确保表中只有一条记录
            raise ValidationError('There can be only one ipdistribution instance')
        super().save(force_insert, force_update, using, update_fields)


@clean_register.register
class ExternalIPTopFive(models.Model):
    ips = ArrayField(models.CharField('IP地址', max_length=20), size=5)
    count = ArrayField(models.IntegerField('出现数量'), size=5)
    update_time = models.DateTimeField('更新时间')

    class Meta:
        verbose_name = '资产中心——外联资产Top5'
        ordering = ('-id', )


@clean_register.register
class ProtocolPortRank(models.Model):
    src_port = JSONField('源端口', encoder=DjangoJSONEncoder)
    dst_port = JSONField('目的端口', encoder=DjangoJSONEncoder)
    update_time = models.DateTimeField('更新时间')

    class Meta:
        verbose_name = '流量中心——今日端口统计'
        ordering = ('-id', )


@clean_register.register
class ProtocolIPRank(models.Model):
    src_ip = JSONField('源IP', encoder=DjangoJSONEncoder)
    dst_ip = JSONField('目的IP', encoder=DjangoJSONEncoder)
    update_time = models.DateTimeField('更新时间')

    class Meta:
        verbose_name = '流量中心——今日IP统计'
        ordering = ('-id', )


@clean_register.register
class AttackIPRank(models.Model):
    src_ip = JSONField('源IP', encoder=DjangoJSONEncoder)
    dst_ip = JSONField('目的IP', encoder=DjangoJSONEncoder)
    update_time = models.DateTimeField('更新时间')

    class Meta:
        verbose_name = '攻击画像——攻击源和被攻击IP'
        ordering = ('-id', )


@clean_register.register
class AlertWeekTrend(models.Model):
    """
    安全态势——异常行为
    各种威胁类型类别每天的趋势
    """
    scan = JSONField('扫描探测今日趋势', encoder=DjangoJSONEncoder)
    flaw = JSONField('漏洞利用今日趋势', encoder=DjangoJSONEncoder)
    penetration = JSONField('后期渗透今日趋势', encoder=DjangoJSONEncoder)
    apt = JSONField('APT今日趋势', encoder=DjangoJSONEncoder)
    other = JSONField('其他今日趋势', encoder=DjangoJSONEncoder)
    update_time = models.DateTimeField('更新时间')

    class Meta:
        verbose_name = '安全态势——异常行为'
        ordering = ('-update_time',)
