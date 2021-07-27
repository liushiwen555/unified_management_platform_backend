from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.utils import timezone
from rest_framework.exceptions import ValidationError


class Setting(models.Model):
    """
    admin对用户模块进行设置，会在第一次获取信息时创建记录
    lockout_threshold    最大登录失败次数
    lockout_duration     锁定时间，分钟
    reset_lockout_counter_after  重新计数时间，分钟
    login_timeout_duration  无操作自动退出时间，分钟
    ip_limit_enable      是否启用登陆IP限制
    allowed_ip           允许登录的IP列表
    disk_alert_percent   存储告警阈值, 百分比
    disk_clean_percent   存储覆盖阈值, 百分比
    cpu_alert_percent    cpu使用率告警阈值, 百分比
    """
    BACKGROUND_DARK = 'dark'
    BACKGROUND_LIGHT = 'light'
    BACKGROUND_CHOICES = (
        (BACKGROUND_DARK, '深色背景'),
        (BACKGROUND_LIGHT, '浅色背景'),
    )
    THEME_GREEN = 'green'
    THEME_BLUE = 'blue'
    THEME_RED = 'red'
    THEME_ORANGE = 'orange'
    THEME_CHOICES = (
        (THEME_GREEN, '绿色'),
        (THEME_BLUE, '蓝色'),
        (THEME_RED, '红色'),
        (THEME_ORANGE, '橘色'),
    )

    lockout_threshold = models.IntegerField('最大登录失败次数', default=5,
                                            validators=[MinValueValidator(1)])
    lockout_duration = models.IntegerField('锁定时间，分钟', default=30,
                                           validators=[MinValueValidator(1)])
    change_psw_duration = models.IntegerField('未更换密码告警，天', default=90,
                                              validators=[MinValueValidator(1)])
    reset_lockout_counter_after = models.IntegerField('重新计数时间，分钟', default=15,
                                                      validators=[
                                                          MinValueValidator(1)])
    login_timeout_duration = models.IntegerField('无操作自动退出时间，分钟', default=15,
                                                 validators=[
                                                     MinValueValidator(1)])
    ip_limit_enable = models.BooleanField('是否启用登陆IP限制', default=False)
    all_remote_ip_limit_enable = models.BooleanField('是否禁用所有的远程IP登录',
                                                     default=False)
    allowed_ip = ArrayField(models.GenericIPAddressField(),
                            verbose_name='允许登录的IP', default=list)
    disk_alert_percent = models.IntegerField('存储告警阈值', default=80,
                                             validators=[MinValueValidator(80),
                                                         MaxValueValidator(95)])
    disk_clean_percent = models.IntegerField('存储覆盖阈值', default=85,
                                             validators=[MinValueValidator(85),
                                                         MaxValueValidator(95)])
    cpu_alert_percent = models.IntegerField('cpu使用率告警阈值', default=80,
                                            validators=[MinValueValidator(80),
                                                        MaxValueValidator(95)])
    memory_alert_percent = models.IntegerField('内存使用率告警阈值', default=80,
                                               validators=[
                                                   MinValueValidator(80),
                                                   MaxValueValidator(95)])
    background = models.CharField('背景色', choices=BACKGROUND_CHOICES,
                                  max_length=20, default=BACKGROUND_DARK,
                                  help_text='主题背景色')
    theme = models.CharField('主题色', choices=THEME_CHOICES, max_length=20,
                             default=THEME_GREEN, help_text='主题色')
    security_center = models.IntegerField('删除安全中心的数据范围', default=3,
                                          validators=[MinValueValidator(1),
                                                      MaxValueValidator(6)])

    class Meta:
        verbose_name = '用户设置'

    def __str__(self):
        return '用户设置'

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        if Setting.objects.exists() and not self.pk:
            # 确保表中只有一条记录
            raise ValidationError('There can be only one setting instance')
        # You can not enable ip limit with allowed ip table empty.
        if self.ip_limit_enable and not self.allowed_ip:
            self.ip_limit_enable = False
        if self.allowed_ip:
            self.allowed_ip = list(set(self.allowed_ip))
        super(Setting, self).save(force_insert, force_update, using,
                                  update_fields)


class Time(models.Model):
    """
    新建一个 time model 专门用来构造假数据
    """
    time = models.DateTimeField(default=timezone.now)


class IP(models.Model):
    """
    新建一个 ip model 专门用来构造假数据
    """
    address = models.GenericIPAddressField()
    net_mask = models.GenericIPAddressField()
    gateway = models.GenericIPAddressField()


class Location(models.Model):
    country = models.CharField('国家', max_length=20, default='中国')
    province = models.CharField('省份', max_length=20, null=True, default='北京')
    city = models.CharField('城市', max_length=20, null=True, default='北京')
    latitude = models.FloatField('纬度', null=True, default=39.904989)
    longitude = models.FloatField('经度', null=True, default=116.405285)

    class Meta:
        verbose_name = '客户地理位置'
