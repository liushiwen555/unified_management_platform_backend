from typing import Dict

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from setting.models import Setting
from utils.base_testcase import BaseViewTest, ConfigEngineerPermission,\
    AdminPermission
from utils.core.exceptions import CustomError


@pytest.mark.django_db
class TestSystemSecurityView(BaseViewTest):
    @ConfigEngineerPermission.authenticate_read_only
    def test_permission(self, all_client: Dict[str, APIClient], user: str,
                        expect_code: int):
        client = all_client[user]

        response = client.get(
            reverse('system-security'),
        )

        assert response.status_code == expect_code

    @ConfigEngineerPermission.config_engineer_permission_200
    def test_permission(self, all_client: Dict[str, APIClient], user: str,
                        expect_code: int):
        client = all_client[user]

        target = ['system-security']
        body = [
            {"disk_alert_percent": 95, "disk_clean_percent": 90,
             "cpu_alert_percent": 80, "memory_alert_percent": 80},
        ]

        for i in range(len(target)):
            url = reverse(target[i])
            response = client.patch(url, body[i], format='json')

            assert response.status_code == expect_code

    @AdminPermission.admin_permission_200
    def test_admin_permission(self, all_client: Dict[str, APIClient],
                              user: str, expect_code: int):
        client = all_client[user]

        target = ['setting-theme']
        body = [
            {'theme': 'green', 'background': 'dark'}
        ]

        for i in range(len(target)):
            url = reverse(target[i])
            response = client.patch(url, body[i], format='json')

            assert response.status_code == expect_code



    def test_update_setting(self, config_client: APIClient):
        response = config_client.patch(
            reverse('system-security'),
            data={
                'disk_clean_percent': 90,
            },
            format='json',
        )

        setting = Setting.objects.get()
        assert setting.disk_clean_percent == 90

    def test_update_theme(self, admin_client: APIClient):
        response = admin_client.patch(
            reverse('setting-theme'),
            data=dict(
                background=Setting.BACKGROUND_LIGHT,
                theme=Setting.THEME_RED,
            ),
            format='json'
        )
        setting = Setting.objects.get()

        assert response.status_code == status.HTTP_200_OK
        assert setting.background == Setting.BACKGROUND_LIGHT
        assert setting.theme == Setting.THEME_RED

    def test_set_ip_limit(self, config_client: APIClient):
        response = config_client.patch(
            reverse('ip-limit'),
            data=dict(
                ip_limit_enable=False,
                allowed_ip=[]
            ),
            format='json',
            # HTTP_X_REAL_IP='1.1.1.1'
        )

        assert response.status_code == status.HTTP_200_OK
        # 设置了限制ip登录时，必须要传allowed_ip
        response = config_client.patch(
            reverse('ip-limit'),
            data=dict(
                ip_limit_enable=True,
                allowed_ip=[]
            ),
            format='json',
        )

        assert response.status_code == CustomError.status_code
        assert response.data == CustomError(
            error_code=CustomError.IP_TABLES_NULL_ERROR).detail

    def test_set_ip_limit_banned(self, config_client: APIClient):
        response = config_client.patch(
            reverse('ip-limit'),
            data=dict(
                ip_limit_enable=True,
                allowed_ip=['127.0.0.1']
            )
        )
        # ban掉1.1.1.1的ip，下次使用1.1.1.1的ip访问会失败
        response = config_client.get(
            reverse('ip-limit'),
            HTTP_X_REAL_IP='1.1.1.1'
        )
        assert response.status_code == CustomError.status_code

        # 恢复ip设置
        response = config_client.patch(
            reverse('ip-limit'),
            data=dict(
                ip_limit_enable=False,
                allowed_ip=[]
            )
        )
