from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from rest_framework.authtoken.models import Token

from utils.core.field_error import UserField

GROUP_AUDITOR = 'Auditor'
GROUP_ADMIN = 'Admin'
GROUP_CONFIG_ENGINEER = 'Config_Engineer'
GROUP_SECURITY_ENGINEER = 'Security_Engineer'

GROUP_CHOICES = (
    (GROUP_ADMIN, '管理员'),
    (GROUP_AUDITOR, '审计工程师'),
    (GROUP_CONFIG_ENGINEER, '配置工程师'),
    (GROUP_SECURITY_ENGINEER, '安全工程师'),
)

NON_ADMIN_GROUPS = [GROUP_AUDITOR, GROUP_CONFIG_ENGINEER,
                    GROUP_SECURITY_ENGINEER]
ALL_GROUPS = [GROUP_AUDITOR, GROUP_CONFIG_ENGINEER, GROUP_SECURITY_ENGINEER,
              GROUP_ADMIN]
USERNAME_MAX_LENGTH = 16
USERNAME_MIN_LENGTH = 6
username_validator = RegexValidator(
    regex=r'^[a-zA-Z][a-zA-Z0-9]*$',
    message='用户名只能包含大小写字母数字，必须以字母开头，最长{}位, 最短{}位'.format(
        USERNAME_MAX_LENGTH, USERNAME_MIN_LENGTH))
special_characters = r'~\!@#\$%\^\&\(\)\-_\+,=\.;\'\?\[\]\{\}'

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 16
password_regex = (r'^(?![A-Za-z0-9]+$)'
                  r'(?![0-9{0}]+$)'
                  r'(?![{0}A-Za-z]+$)'
                  r'([{0}0-9A-Za-z]{{8,16}})$'.format(special_characters))
password_validator = RegexValidator(
    regex=password_regex,
    message='密码由大小写英文字母/数字/符号至少3种组成，{}-{}位字符'.format(
        PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH
    ))


class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, username, email=None, password=None, **extra_fields):
        username = self.model.normalize_username(username)
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user


class Group(models.Model):
    name = models.CharField('名称', max_length=32, unique=True,
                            choices=GROUP_CHOICES)

    class Meta:
        verbose_name = '用户组'
        ordering = ['id']


class User(AbstractBaseUser):
    username = models.CharField('用户名', max_length=USERNAME_MAX_LENGTH,
                                validators=[username_validator], unique=True,
                                help_text='用户名',
                                error_messages={
                                    'unique': UserField.NAME_DUPLICATE})
    email = models.EmailField('email地址', blank=True)
    is_active = models.BooleanField('启用状态', default=True,
                                    help_text='启用状态')
    date_joined = models.DateTimeField('创建时间', auto_now_add=True)
    group = models.ForeignKey(Group, help_text='用户组', on_delete=models.SET_NULL,
                              null=True)
    description = models.CharField(max_length=100, help_text='备注', blank=True)
    last_modify = models.DateTimeField('修改时间', auto_now=True)
    un_modify_passwd = models.BooleanField('是否长时间未修改密码', default=False)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['group']

    class Meta:
        verbose_name = '用户'
        ordering = ['-id']

    def __str__(self):
        return '{} {} {}'.format(self.id, self.username, self.group)

    def get_full_name(self):
        return self.username

    def get_short_name(self):
        return self.username


class UserExtension(models.Model):
    name = models.CharField('用户名', max_length=32, unique=True)
    count = models.IntegerField('连续登陆失败次数', default=0)
    banned = models.BooleanField('被禁状态', default=False)
    last_failure = models.DateTimeField('上一次登陆失败时间', null=True)
    last_login = models.DateTimeField('上一次请求登录时间', null=True)
    ip = models.GenericIPAddressField('上一次请求登录的IP', null=True)
    last_change_psd = models.DateTimeField('上一次修改密码', null=True,
                                           default=timezone.now)
    description = models.CharField('备注信息', max_length=100, null=True,
                                   blank=True)

    class Meta:
        verbose_name = '用户扩展信息'

    def __str__(self):
        return '{} {}'.format(self.id, self.name)

    @classmethod
    def abnormal_login(cls):
        return cls.objects.filter(
            models.Q(last_login__hour__gte=0, last_login__hour__lte=6) |
            models.Q(last_login__hour__gte=22,
                     last_login__hour__lte=23)).order_by(
            '-last_login')


# triggered whenever a new user has been created and saved to the db
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_auth_token(sender, instance=None, created=False, **kwargs):
    if created:
        Token.objects.create(user=instance)
