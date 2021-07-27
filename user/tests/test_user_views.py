from typing import Dict

import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from user.models import GROUP_AUDITOR, UserExtension, Group
from utils.base_testcase import BaseViewTest, BaseUser, AdminPermission
from utils.core.exceptions import CustomError
from utils.core.field_error import UserField

User = get_user_model()


@pytest.mark.django_db
class TestUserView(BaseViewTest):
    @pytest.fixture(scope='class')
    def group(self) -> Group:
        return Group.objects.get(name=GROUP_AUDITOR)

    @AdminPermission.authenticate_read_only
    def test_authenticate_permissions(self, all_client: Dict[str, APIClient],
                                      user: str, expect_code: int):
        client = all_client[user]
        if user != BaseUser.anonymous:
            user = User.objects.get(username=user)
            user_id = user.id
        else:
            user_id = 1

        targets = ['user-view-detail']

        for i in range(len(targets)):
            response = client.get(reverse(targets[i], args=(user_id,)))
            assert response.status_code == expect_code

    @AdminPermission.admin_permission_200
    def test_user_view_list_permissions(self, all_client: Dict[str, APIClient],
                                        user: str, expect_code: int):
        """
        用于列表只允许管理员能够查看
        """
        client = all_client[user]

        targets = ['user-view-list']
        args = [None]

        for i in range(len(targets)):
            if args[i]:
                response = client.get(reverse(targets[i], args=(args[i],)))
            else:
                response = client.get(reverse(targets[i]))
            assert response.status_code == expect_code

    @AdminPermission.admin_permission_201
    def test_permission_create(self, all_client: Dict[str, APIClient],
                               user: str, expect_code: int):
        client = all_client[user]

        targets = ['user-view-list']
        args = [None]
        datas = [
            {'username': 'dddttt', 'password1': BaseUser.right_password,
             'password2': BaseUser.right_password, 'is_active': True,
             'group': GROUP_AUDITOR},
        ]

        for i in range(len(targets)):
            if args[i]:
                url = reverse(targets[i], args=(args[i],))
            else:
                url = reverse(targets[i])
            response = client.post(
                url, data=datas[i], format='json'
            )
            assert response.status_code == expect_code

    @AdminPermission.admin_permission_200
    def test_permission_update(self, all_client: Dict[str, APIClient],
                               user: str, expect_code: int, group: Group):
        client = all_client[user]

        user = User.objects.create_user('test', password='Test6666',
                                        group=group)
        user.save()

        targets = ['user-view-detail']
        args = [user.id]
        datas = [
            {'group': GROUP_AUDITOR, 'is_active': False, 'description': ''}
        ]

        for i in range(len(targets)):
            if args[i]:
                url = reverse(targets[i], args=(args[i],))
            else:
                url = reverse(targets[i])
            response = client.put(
                url, data=datas[i], format='json'
            )
            assert response.status_code == expect_code

    @AdminPermission.admin_permission_204
    def test_permission_delete(self, all_client: Dict[str, APIClient],
                               user: str, expect_code: int, group: Group):
        client = all_client[user]

        user = User.objects.create_user('test', password='Test6666',
                                        group=group)

        targets = ['user-view-detail']
        args = [user.id]

        for i in range(len(targets)):
            if args[i]:
                url = reverse(targets[i], args=(args[i],))
                url = url + '?password={}'.format(BaseUser.right_password)
            else:
                url = reverse(targets[i])
            response = client.delete(url)
            assert response.status_code == expect_code

    def test_create_duplicate_user(self, admin_client: APIClient, group: Group):
        user = User.objects.create_user(username='hello123',
                                        password=BaseUser.right_password,
                                        group=group)

        response = admin_client.post(
            reverse('user-view-list'),
            data=dict(
                username='hello123',
                password1=BaseUser.right_password,
                password2=BaseUser.right_password,
                group=GROUP_AUDITOR,
                is_active=True,
            ),
            format='json'
        )

        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.USERNAME_ALREADY_EXISTS_ERROR).detail

    def test_create_wrong_username_user(self, admin_client: APIClient):
        """
        创建用户名不符合规范的用户
        """
        response = admin_client.post(
            reverse('user-view-list'),
            data=dict(
                username='1111',
                password1=BaseUser.right_password,
                password2=BaseUser.right_password,
                group=GROUP_AUDITOR,
            ),
            format='json',
        )
        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.USERNAME_FORMAT_ERROR).detail

    def test_login_wrong_username(self, client: APIClient):
        """
        登录时，使用不规范的用户名
        """
        response = client.post(
            reverse('user-login'),
            data=dict(
                username='1111',
                password=BaseUser.right_password,
            ),
            REMOTE_ADDR='127.0.0.1'
        )

        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.USERNAME_FORMAT_ERROR).detail

    def test_create_user(self, admin_client: APIClient):
        data = dict(
            username='test123',
            password1=BaseUser.right_password,
            password2=BaseUser.right_password,
            group=GROUP_AUDITOR,
            is_active=False,
        )
        response = admin_client.post(
            reverse('user-view-list'),
            data=data,
            format='json',
        )
        user = User.objects.get(username='test123')
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['username'] == data['username']
        assert response.data['group'] == data['group']
        assert not user.is_active

    def test_create_wrong_password_user(self, admin_client: APIClient):
        """
        创建密码不规范的用户
        """
        # 密码不符合规范
        response = admin_client.post(
            reverse('user-view-list'),
            data=dict(
                username='test123',
                password1='bl6666',
                password2='bl6666',
                group=GROUP_AUDITOR,
                is_active=True,
            ),
            format='json',
        )
        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.PASSWORD_FORMAT_ERROR).detail

        # 两次密码不一致
        response = admin_client.post(
            reverse('user-view-list'),
            data=dict(
                username='test123',
                password1=BaseUser.right_password,
                password2='Bl@6666661',
                group=GROUP_AUDITOR,
                is_active=True,
            ),
            format='json',
        )
        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.PASSWORD_NOT_CONSISTENT).detail

    def test_change_password(self, client: APIClient, group: Group):
        user = User.objects.create_user('test12', password='Bl@666666',
                                        group=group)
        user_ext, created = UserExtension.objects.get_or_create(
            name=user.username)

        client.force_authenticate(user=user)
        response = client.post(
            reverse('change-password'),
            data=dict(
                password='Bl@666666',
                new_password1='Bl@555555',
                new_password2='Bl@555555',
            ),
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK

        # 错误的密码格式
        response = client.post(
            reverse('change-password'),
            data=dict(
                password='Bl@555555',
                new_password1='Bl5555',
                new_password2='Bl5555',
            ),
            format='json'
        )
        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.PASSWORD_FORMAT_ERROR).detail

        # 两次密码不一致
        response = client.post(
            reverse('change-password'),
            data=dict(
                password='Bl@555555',
                new_password1='Bl555566',
                new_password2='Bl555555',
            ),
            format='json'
        )
        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.PASSWORD_FORMAT_ERROR).detail

    def test_reset_password(self, admin_client: APIClient, group: Group):
        user = User.objects.create_user('test12', password='Bl@666666',
                                        group=group)
        user_ext, created = UserExtension.objects.get_or_create(
            name=user.username)

        response = admin_client.post(
            reverse('reset-password', kwargs={'pk': user.id}),
            data=dict(
                password='Bl@666666',
                new_password1='Bl@555555',
                new_password2='Bl@555555',
            ),
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK

        # 错误的密码格式
        response = admin_client.post(
            reverse('reset-password', kwargs={'pk': user.id}),
            data=dict(
                password='Bl@666666',
                new_password1='Bl5555',
                new_password2='Bl5555',
            ),
            format='json'
        )
        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.PASSWORD_FORMAT_ERROR).detail

        # 两次密码不一致
        response = admin_client.post(
            reverse('reset-password', kwargs={'pk': user.id}),
            data=dict(
                password='Bl@666666',
                new_password1='Bl@555566',
                new_password2='Bl@555555',
            ),
            format='json'
        )
        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.PASSWORD_NOT_CONSISTENT).detail

    def test_description_exceed_length(self, admin_client: APIClient):
        """
        备注信息不能超过100长度
        """
        response = admin_client.post(
            reverse('user-view-list'),
            data=dict(
                username='test123',
                password1='Bl@666666',
                password2='Bl@666666',
                group=GROUP_AUDITOR,
                is_active=True,
                description='1' * 101
            ),
            format='json',
        )

        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.FIELD_ERROR,
            message=UserField.DESCRIPTION_LENGTH_EXCEED.format(
                max_length=100)).detail

    def test_view_user_detail(self, config_client: APIClient, group: Group,
                              admin_client: APIClient):
        """
        用户只能查看自己的信息，查看其他用户的信息时返回403
        管理员能看到任何人的
        """
        other = User.objects.create_user(username='qwe123',
                                         password=BaseUser.right_password,
                                         group=group)
        response = config_client.get(
            reverse('user-view-detail', args=(other.id,)),
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

        user = User.objects.get(username=BaseUser.config_engineer_name)
        response = config_client.get(
            reverse('user-view-detail', args=(user.id,))
        )

        assert response.status_code == status.HTTP_200_OK

        response = admin_client.get(
            reverse('user-view-detail', args=(other.id, ))
        )

        assert response.status_code == status.HTTP_200_OK

    def test_get_user_list(self, admin_client: APIClient):
        group = Group.objects.get(name=GROUP_AUDITOR)
        for i in range(10):
            if i % 2 == 0:
                is_active = False
            else:
                is_active = True
            user = User.objects.create_user(
                username='test2ss' + str(i), password=BaseUser.right_password,
                group=group, is_active=is_active
            )

        response1 = admin_client.get(
            reverse('user-view-list'),
            data={'group': GROUP_AUDITOR, 'is_active': False},
            format='json'
        )

        assert response1.data['count'] == User.objects.filter(
            group=group, is_active=False).count()

        response2 = admin_client.get(
            reverse('user-view-list'),
            data={'group': GROUP_AUDITOR, 'is_active': True},
            format='json'
        )

        assert response2.data['count'] == User.objects.filter(
            group=group, is_active=True).count()
