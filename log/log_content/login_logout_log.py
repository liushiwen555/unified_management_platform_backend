"""
登录登出日志
"""
from typing import Dict

from django.contrib.auth import get_user_model
from django.urls import resolve

from log.log_content.log_generator import LogGenerator, LogConfig, HookAbstract
from log.models import UnifiedForumLog, DeviceAllAlert
from setting.models import Setting
from user.models import UserExtension

login_logout_config = LogConfig()
User = get_user_model()


class LoginLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_LOGIN,
    }
    log_category = UnifiedForumLog.CATEGORY_LOGIN_LOGOUT


class LogoutLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_LOGOUT,
    }
    log_category = UnifiedForumLog.CATEGORY_LOGIN_LOGOUT


@login_logout_config.register('user-login', 'POST')
class LoginLogGenerator(LoginLogMixin, LogGenerator):
    """
    用户登录日志
    日志格式
    登录成功
    登录失败
    登录失败达到上限，账号锁定15分钟
    """
    content_template = '登录{result}'
    fail_content_template = '密码输入错误{threshold}次，账号锁定{duration}分钟'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.get_user()
        self.user_extension = None
        self.setting = None

    def get_user(self) -> User:
        """
        获取用户信息，如果用户登录成功，就直接用self.user，如果登录失败，需要另外根据
        username去查数据库
        :return user
        """
        if self.user.is_authenticated:
            return self.user

        try:
            username = self.request_body['username']
            user = User.objects.get(username=username)
            self.user = user
        except User.DoesNotExist:
            return self.user

    def get_content(self) -> str:
        if self.result:
            content = self.content_template.format(
                result=self.resp_result)
        else:
            content = self.process_failure_login()
        return content

    def process_failure_login(self):
        """
        当登录失败的时候，需要额外派单是否达到了登录失败上限，而且还要判断是否告警
        :return
        登录失败
        登录失败达到上限5，账号锁定15分钟
        """
        if self.user.is_anonymous:
            # 匿名用户登录失败不做特殊处理
            return self.content_template.format(
                result=self.resp_result
            )
        self.user_extension, _ = UserExtension.objects.get_or_create(
            name=self.user.username)
        self.setting, setting_exist = Setting.objects.get_or_create(id=1)
        if self.user_extension.count >= self.setting.lockout_threshold:
            content = self.fail_content_template.format(
                threshold=self.setting.lockout_threshold,
                duration=self.setting.lockout_duration,
            )
            return content
        else:
            return self.content_template.format(
                result=self.resp_result
            )


@login_logout_config.register('user-logout', 'GET', additional_info=True)
class LogoutLogGenerator(LogoutLogMixin, LogGenerator, HookAbstract):
    """
    登出日志
    日志格式:
    安全登出
    超时登出
    """
    content_template = '安全登出, {result}'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.username = kwargs['username']
        self.group = kwargs['group']

    def get_content(self) -> str:
        content = self.content_template.format(
            result=self.resp_result
        )

        return content

    def get_group(self) -> str:
        return self.group

    def get_username(self) -> str:
        return self.username

    @classmethod
    def get_previous(cls, request):
        user = request.user
        if user.is_anonymous:
            return {'username': user.username, 'group': ''}
        return {'username': user.username, 'group': user.group.name}
