from typing import Dict

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from utils.base_testcase import ConfigEngineerPermission, BaseViewTest
from base_app.factory_data import DeviceFactory
from snmp.factory_data import SNMPDataFactory
from statistic.factory_data import LogCenterFactory


@pytest.mark.django_db
class TestPermission(BaseViewTest):
    @ConfigEngineerPermission.authenticate_read_only
    def test_permissions(self, all_client: Dict[str, APIClient], user: str,
                         expect_code: int):
        client = all_client[user]
        target = ['main-view', 'assets-center', 'monitor-center', 'log-center',
                  'log-total', 'log-day-trend', 'log-hour-trend']

        for i in target:
            response = client.get(
                reverse(i),
            )

            assert response.status_code == expect_code

    def test_log_center(self, config_client: APIClient):
        LogCenterFactory.create_batch(20)

        response = config_client.get(
            reverse('log-center')
        )

        data = response.data
        assert len(data['collect']['data']) == 10
        assert len(data['parsed']['data']) == 10
        assert len(data['update_time']) == 10

    def test_snmp_data(self, config_client: APIClient):
        device = DeviceFactory.create_normal()
        snmp_data = SNMPDataFactory.create(device=device)

        response = config_client.get(
            reverse('snmp-data'),
            data={
                'ip': device.ip,
                'name': device.name,
            },
            format='json'
        )

        assert response.status_code == 200