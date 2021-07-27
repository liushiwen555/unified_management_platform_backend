import pytest

from django.contrib.auth import get_user_model
from django.urls import reverse
from faker import Faker
from rest_framework.test import APIClient

from utils.base_testcase import BaseUser
from log.models import UnifiedForumLog
from log.tests.test_log_generator.base_testcase import BaseLogTest
from utils.constants import GROUP_NAME_DICT
from user.models import GROUP_AUDITOR, GROUP_SECURITY_ENGINEER,\
    GROUP_CONFIG_ENGINEER, Group
from log.security_event import UserEventLog

fake = Faker()
User = get_user_model()


class TestUpdateUserAuthLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_AUTH
    category = UnifiedForumLog.CATEGORY_USER_MANAGEMENT

    UPDATE_USER = 'user-view-detail'
    ADD_USER = 'user-view-list'

    @pytest.fixture(scope='class')
    def group(self) -> Group:
        return Group.objects.get(name=GROUP_CONFIG_ENGINEER)

    def format_content(self, method: str, user: str, status_code: int,
                       previous: str, current: str = None,
                       status: int = None):
        if not current or method in ['启用', '停用']:
            return f'{method}【{GROUP_NAME_DICT[previous]}{user}】账号, ' \
                   f'{self.status_desc(status_code)}'
        else:
            return f'编辑【{GROUP_NAME_DICT[previous]}{user}】为' \
                   f'【{GROUP_NAME_DICT[current]}】,' \
                   f' {self.status_desc(status_code)}'

    def test_update_user_auth(self, admin_client: APIClient, group: Group):
        """
        编辑 【旧角色】【用户】为【新角色】, 【启用/停用】【用户】账号
        """
        user = User.objects.create_user('test123', password='Bl666666',
                                        group=group)
        group_name = user.group.name
        data = dict(
            group=GROUP_CONFIG_ENGINEER,
            is_active=True,
        )
        response = admin_client.patch(
            reverse(self.UPDATE_USER, args=(user.id,)),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '编辑', user.username, response.status_code, group_name,
            current=data['group']
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '启用', user.username, response.status_code, group_name
        ))
        assert log.exists()
        self.check_type_and_category(log[0])

    def test_delete_user(self, admin_client: APIClient, group: Group):
        user = User.objects.create_user('test123', password='Bl666666',
                                        group=group)
        group_name = user.group.name
        response = admin_client.delete(
            reverse(self.UPDATE_USER, args=(user.id,)),
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '删除', user.username, response.status_code, group_name
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_post_user(self, admin_client: APIClient):
        data = {'username': 'dddttt123', 'password1': BaseUser.right_password,
                'password2': BaseUser.right_password, 'group': GROUP_SECURITY_ENGINEER,
                'is_active': True}

        response = admin_client.post(
            reverse(self.ADD_USER),
            data=data,
            format='json'
        )
        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '添加', data['username'], response.status_code, data['group']
        ))

        assert log.exists()
        self.check_type_and_category(log[0])
        assert UserEventLog.get_queryset(content__contains='添加').exists()


class TestResetPasswordLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_AUTH
    category = UnifiedForumLog.CATEGORY_USER_MANAGEMENT

    RESET_VIEW = 'reset-password'

    def format_content(self, user: str, group: str, status: int):
        return f'重置【{group}{user}】密码, {self.status_desc(status)}'

    @pytest.fixture(scope='class')
    def group(self) -> Group:
        return Group.objects.get(name=GROUP_CONFIG_ENGINEER)

    def test_reset_password(self, admin_client: APIClient, group: Group):
        user = User.objects.create_user(
            username='test123', password=BaseUser.right_password, group=group)
        response = admin_client.post(
            reverse(self.RESET_VIEW, args=(user.id, )),
            data={
                'password': BaseUser.right_password,
                'new_password1': BaseUser.right_password,
                'new_password2': BaseUser.right_password,
            },
            format='json'
        )

        logs = UnifiedForumLog.objects.filter(content=self.format_content(
            user.username, GROUP_NAME_DICT[user.group.name],
            response.status_code
        ))

        assert logs.exists()
        self.check_type_and_category(logs[0])
