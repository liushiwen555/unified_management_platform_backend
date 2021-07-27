from typing import Dict

import pytest
from django.urls import reverse
from django.utils.http import urlencode
from django.db.models import Q
from faker import Faker
from rest_framework import status
from rest_framework.test import APIClient

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from utils.base_testcase import BaseViewTest, authenticate_read_only, \
    config_engineer_permission_delete, config_engineer_permission_update, \
    config_engineer_permission_create
from utils.core.exceptions import CustomError
from snmp.factory_data import SNMPSettingFactory, SNMPTemplateFactory, SNMPRuleFactory
from unified_log.factory_data import LogProcessTemplateFactory
from base_app.serializers import LogSettingSerializer
from snmp.serializers import SNMPSettingSerializer
from snmp.models import SNMPSetting

fake = Faker()


class TestDeviceSetting(BaseViewTest):
    @authenticate_read_only
    def test_read_permissions(self, all_client: Dict[str, APIClient], user: str,
                              expect_code: int):
        device = DeviceFactory.create_normal()
        client = all_client[user]
        target = ['device-manage-log-setting', 'device-manage-snmp-setting']

        for i in target:
            url = reverse(i, args=(device.id, ))
            response = client.get(url)

            assert response.status_code == expect_code

    @config_engineer_permission_update
    def test_update_permission(self, all_client: Dict[str, APIClient], user: str,
                               expect_code: int):
        device = DeviceFactory.create_normal()
        setting = SNMPSettingFactory.create(device=device)
        template = LogProcessTemplateFactory.create()
        client = all_client[user]
        target = ['device-manage-snmp-setting', 'device-manage-log-setting']
        body = [
            {
                'status': True,
                'frequency': 5,
                'overtime': 5,
                'port': 161,
                'version': 2,
                'community': 'bolean',
                'username': None,
                'security_level': 1,
                'template': setting.template.id,
                'auth': 1,
                'auth_password': None,
                'priv': 1,
                'priv_password': None
            },
            {
                'log_status': True,
                'log_template': template.id,
            }
        ]
        for i in range(len(target)):
            response = client.put(
                reverse(target[i], args=(device.id, )),
                data=body[i], format='json'
            )
            assert response.status_code == expect_code

    def test_update_snmp_setting(self, config_client: APIClient):
        """
        snmpsetting里的启用状态字段是资产的性能监控状态字段，所以更新snmpsetting的时候
        资产上的字段也要相应更新
        """
        device = DeviceFactory.create_normal()
        setting = SNMPSettingFactory.create(device=device)
        Device.objects.filter(id=device.id).update(monitor=False)

        serializer = SNMPSettingSerializer(setting)
        data = serializer.data
        data['status'] = True
        data['community'] = 'test123'
        response = config_client.put(
            reverse('device-manage-snmp-setting', args=(device.id, )),
            data=data, format='json'
        )

        assert SNMPSetting.objects.filter(community='test123',
                                          device_id=device.id).exists()
        assert Device.objects.filter(id=device.id, monitor=True).exists()

    def test_update_log_setting(self, config_client: APIClient):
        template = LogProcessTemplateFactory.create()
        device = DeviceFactory.create_normal(log_status=False)

        data = {'log_status': True, 'log_template': template.id}
        response = config_client.put(
            reverse('device-manage-log-setting', args=(device.id, )),
            data=data, format='json'
        )

        assert Device.objects.filter(id=device.id, log_status=True,
                                     log_template__id=template.id).exists()
