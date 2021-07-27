from typing import List, Dict

from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.postgres.fields import JSONField, ArrayField
from django.core.serializers.json import DjangoJSONEncoder
from rest_framework.exceptions import ValidationError

from base_app.models import Device
from statistic.models import clean_register


class BaseRule(models.Model):
    SYSTEM_ADD = 1
    MANUAL_ADD = 2
    ADD_TYPE_CHOICES = (
        (SYSTEM_ADD, '系统内置'),
        (MANUAL_ADD, '用户添加')
    )
    brand = models.CharField('厂商', max_length=10, blank=True, null=True,
                             help_text='厂商')
    hardware = models.CharField('型号', max_length=10, blank=True, null=True,
                                help_text='型号')
    add = models.IntegerField('添加方式', choices=ADD_TYPE_CHOICES,
                              default=SYSTEM_ADD, help_text='添加方式')
    update_time = models.DateTimeField('更新时间', auto_now=True,
                                       help_text='更新时间')

    class Meta:
        abstract = True


class SNMPRule(BaseRule):
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

    category = models.IntegerField('系统类别', choices=CATEGORY_CHOICES,
                                   help_text='资产类别')
    type = models.IntegerField('系统类型', choices=TYPE_CHOICES,
                               help_text='资产类型')
    name = models.CharField('性能监控规则名称', max_length=16, help_text='性能监控规则名称')
    oid = ArrayField(models.CharField(max_length=30), help_text='OID')
    field = models.CharField('字段名', max_length=20, help_text='字段名')
    description = models.CharField('备注', max_length=100, help_text='备注',
                                   blank=True, null=True)

    class Meta:
        verbose_name = 'SNMP性能监控规则'
        ordering = ('-id', )
        unique_together = ('name', 'category', 'type')

    def __str__(self) -> str:
        return f'SNMP Rule: {self.name}'


class SNMPTemplate(BaseRule):
    category = models.IntegerField('资产类别', choices=Device.CATEGORY_CHOICE,
                                   help_text='资产类别')
    type = models.IntegerField('资产类型', choices=Device.DEV_TEMP_TYPE_CHOICES,
                               help_text='资产类型')
    name = models.CharField('性能监控模板名称', max_length=16, help_text='性能监控模板名称')
    rules = models.ManyToManyField(SNMPRule, help_text='SNMP监控规则，id列表')
    description = models.CharField('备注', max_length=100, help_text='备注',
                                   blank=True, null=True)

    class Meta:
        verbose_name = 'SNMP性能监控模板'
        ordering = ('-id', )
        unique_together = ('name', 'category', 'type')

    def __str__(self) -> str:
        return f'SNMP Template: {self.name}'

    def format_rules(self) -> List[Dict[str, str]]:
        """
        将模板里的规则转换为[{'name': 'XXX', 'oid': 'XXX'}]方便展示或者其他操作
        :return: [{'name': 'XXX', 'oid': 'XXX'}]
        """
        rules = self.rules.all()
        result = []
        for r in rules:
            result.append(
                {'name': r.name, 'oid': r.oid}
            )
        return result


class SNMPSetting(models.Model):
    SNMP_V1 = 1
    SNMP_V2 = 2
    SNMP_V3 = 3
    SNMP_VERSIONS = (
        (SNMP_V1, 'SNMP V1'),
        (SNMP_V2, 'SNMP V2'),
        (SNMP_V3, 'SNMP V3'),
    )

    NO_AUTH_NO_PRIV = 1
    AUTH_NO_PRIV = 2
    AUTH_PRIV = 3
    SECURITY_LEVELS = (
        (NO_AUTH_NO_PRIV, '无认证无权限'),
        (AUTH_NO_PRIV, '有认证无权限'),
        (AUTH_PRIV, '有认证有权限'),
    )

    AUTH_MD5 = 1
    AUTH_SHA = 2
    AUTH_PROTOCOLS = (
        (AUTH_MD5, 'MD5认证协议'),
        (AUTH_SHA, 'SHA认证协议'),
    )

    PRIV_DES = 1
    PRIV_AES128 = 2
    PRIV_3DES = 3
    PRIV_AES192 = 4
    PRIV_AES256 = 5
    PRIV_PROTOCOLS = (
        (PRIV_DES, 'DES加密协议'),
        (PRIV_AES128, 'AES128加密协议'),
        (PRIV_3DES, '3DES加密协议'),
        (PRIV_AES192, 'AES192加密协议'),
        (PRIV_AES256, 'AES256加密协议'),
    )

    device = models.OneToOneField(Device, on_delete=models.CASCADE)
    last_run_time = models.DateTimeField(auto_now_add=True, help_text='上次SNMP采集时间')
    frequency = models.IntegerField('采集周期', help_text='采集周期(分)', default=1)
    overtime = models.IntegerField('超时时间', help_text='超时时间(秒)', default=5)
    version = models.IntegerField('SNMP版本', help_text='SNMP版本',
                                  choices=SNMP_VERSIONS, default=SNMP_V1)
    community = models.CharField('读团体字', max_length=32,
                                 help_text='读团体字，V1，V2使用', default='public')
    username = models.CharField('安全名', max_length=32, help_text='安全名',
                                null=True)
    port = models.IntegerField(
        '端口', default=161, validators=[MinValueValidator(1),
                                       MaxValueValidator(65536)])
    security_level = models.IntegerField('安全级别', choices=SECURITY_LEVELS,
                                         null=True, help_text='安全级别',
                                         blank=True)
    auth = models.IntegerField('认证协议', choices=AUTH_PROTOCOLS, null=True,
                               help_text='认证协议', blank=True)
    auth_password = models.CharField('认证密码', max_length=32, null=True,
                                     blank=True)
    priv = models.IntegerField('加密协议', choices=PRIV_PROTOCOLS, null=True,
                               help_text='加密协议', blank=True)
    priv_password = models.CharField('加密密码', max_length=32, null=True,
                                     blank=True)
    template = models.ForeignKey(SNMPTemplate, on_delete=models.SET_NULL,
                                 null=True)

    class Meta:
        verbose_name = '资产SNMP设置'
        ordering = ('-id', )

    def __str__(self):
        return f'SNMP Setting: {self.device.name} {self.template}'

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        """
        一个资产只能有一个setting
        SNMP V1/V2
            只需要community
        SNMP V3:
            必须要选择username和security level
            no auth no priv:
                只需要username
            auth no priv:
                需要选择认证协议，MD5/SHA，并且要有认证密码
            auth priv:
                需要选择认证协议，MD5/SHA，并且要有认证密码
                需要选择加密协议，DES/AES，并且需要有加密密码
        """
        self.check_duplicate_device()
        if self.version in [self.SNMP_V1, self.SNMP_V2]:
            self.check_community()
        else:
            self.check_username_security()
            if self.security_level == self.AUTH_NO_PRIV:
                self.check_auth_no_priv()
            elif self.security_level == self.AUTH_PRIV:
                self.check_auth_priv()
        super().save(force_insert, force_update, using, update_fields)

    def check_community(self):
        if not self.community:
            raise ValidationError('SNMP V1 or SNMP V2 must have community')
        return True

    def check_username_security(self):
        if self.username and self.security_level:
            return True
        raise ValidationError('SNMP V3 must have username and security level')

    def check_auth_no_priv(self):
        if self.auth and self.auth_password:
            return True
        raise ValidationError('Security level `Auth, NoPriv` must have'
                              ' auth_protocol and auth_password')

    def check_auth_priv(self):
        if self.auth and self.auth_password and self.priv and self.priv_password:
            return True
        raise ValidationError('Security level `Auth, Priv` must have'
                              ' auth_protocol and auth_password and'
                              ' priv_protocol and priv_password')

    def check_duplicate_device(self):
        try:
            SNMPSetting.objects.get(device_id=self.device_id)
            if not self.id:
                raise ValidationError('A device must have one and only one snmp setting')
        except SNMPSetting.DoesNotExist:
            pass

        return True


@clean_register.register
class SNMPData(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    update_time = models.DateTimeField(auto_now=True)

    system_info = models.CharField(help_text='系统信息', max_length=256, null=True)
    hostname = models.CharField(help_text='主机名', max_length=256, null=True)
    system_runtime = models.CharField(help_text='系统运行时间', max_length=256,
                                      null=True)
    disk_info = JSONField(encoder=DjangoJSONEncoder, help_text='磁盘读写信息', null=True)
    cpu_in_use = models.FloatField(help_text='CPU使用率', null=True)
    disk_in_use = models.FloatField(help_text='磁盘使用率', null=True)
    disk_total = models.IntegerField(help_text='磁盘总量', null=True)
    disk_used = models.IntegerField(help_text='磁盘使用量', null=True)
    network_in_speed = models.IntegerField(help_text='网卡 in 速度', null=True)
    network_out_speed = models.IntegerField(help_text='网卡 out 速度', null=True)
    network_usage = JSONField(help_text='网卡速度', encoder=DjangoJSONEncoder, null=True)
    cpu_cores = models.IntegerField(help_text='CPU核心数', null=True)
    process_count = models.IntegerField(help_text='进程数', null=True)
    total_memory = models.IntegerField(help_text='总物理内存', null=True)
    memory_used = models.IntegerField(help_text='已使用物理内存', null=True)
    memory_in_use = models.FloatField(help_text='物理内存利用率', null=True)
    total_swap_memory = models.IntegerField(help_text='总虚拟内存', null=True)
    swap_memory_used = models.IntegerField(help_text='已使用虚拟内存', null=True)
    swap_memory_in_use = models.FloatField(help_text='虚拟内存利用率', null=True)
    partition_usage = JSONField(help_text='分区空间使用率', encoder=DjangoJSONEncoder, null=True)

    class Meta:
        verbose_name = '资产性能数据'
        ordering = ('-id', )
