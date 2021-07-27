import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient

from log.models import UnifiedForumLog, DeviceAllAlert
from log.tests.test_log_generator.base_testcase import BaseLogTest
from setting.models import Setting
from user.models import Group, GROUP_AUDITOR
from log.security_event import PasswordErrorEventLog

User = get_user_model()


class TestLoginLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_LOGIN
    category = UnifiedForumLog.CATEGORY_LOGIN_LOGOUT

    LOGIN_URL = 'user-login'

    @pytest.fixture(scope='function')
    def user(self):
        group = Group.objects.get(name=GROUP_AUDITOR)
        user = User.objects.create_user('test', password='Bl666666',
                                        group=group)

        return user

    def format_content(self, status_code: int = None, threshold: int = None,
                       duration: int = None):
        if status_code:
            return f'登录{self.status_desc(status_code)}'
        else:
            return f'密码输入错误{threshold}次，账号锁定{duration}分钟'

    def format_alert(self, username: str, group: str, threshold: int,
                     duration: int):
        return f'{username}（{group}）登录失败{threshold}次达到上限，' \
               f'账号锁定{duration}分钟'

    def test_login(self, client: APIClient, user: User):
        response = client.post(
            reverse(self.LOGIN_URL),
            data={
                'username': user.username,
                'password': 'E11D6EFF57215D01FBC8E374D3C6E352F1D870608899C77B492349129F3F478F'
            },
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_login_user_not_exist(self, client: APIClient):
        response = client.post(
            reverse(self.LOGIN_URL),
            data={
                'username': 'BB654321',
                'password': 'Bl666666'
            },
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            response.status_code), user='AnonymousUser'
        )

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_login_success(self, client: APIClient, user: User):
        response = client.post(
            reverse(self.LOGIN_URL),
            data={
                'username': user.username,
                'password': 'Bl666666'
            },
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content='登录成功')
        assert log.exists()

    def test_login_locked(self, client: APIClient, user: User):
        setting, _ = Setting.objects.get_or_create()
        for _ in range(setting.lockout_threshold):
            client.post(
                reverse(self.LOGIN_URL),
                data={
                    'username': user.username,
                    'password': 'E11D6EFF57215D01FBC8E374D3C6E352F1D870608899C77B492349129F3F478F'
                },
                format='json'
            )

        content = self.format_content(
            threshold=setting.lockout_threshold,
            duration=setting.lockout_duration
        )
        log = UnifiedForumLog.objects.filter(content=content)

        assert log.exists()
        assert PasswordErrorEventLog.get_queryset(content__contains='密码输入错误')
        self.check_type_and_category(log[0])


class TestLogoutLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_LOGOUT
    category = UnifiedForumLog.CATEGORY_LOGIN_LOGOUT

    LOGOUT_URL = 'user-logout'

    def format_content(self, status_code: int):
        return '安全登出, {}'.format(self.status_desc(status_code))

    def test_log_out(self):
        user = User.objects.create_user('hello', password='Bl666666',
                                        group=Group.objects.get(name=GROUP_AUDITOR))
        client = APIClient()
        client.force_authenticate(user=user)
        response = client.get(
            reverse(self.LOGOUT_URL)
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])
