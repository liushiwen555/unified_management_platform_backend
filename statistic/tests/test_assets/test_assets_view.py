from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from base_app.models import Device
from utils.base_testcase import BaseViewTest
from base_app.factory_data import DeviceFactory
from log.factory_data import DeviceAllAlertFactory, SecurityEventFactory
from auditor.bolean_auditor.process_protocol import TodayExternalIP
from utils.helper import safe_divide


class TestDeviceDistributionView(BaseViewTest):
    def test_distribution(self, config_client: APIClient):
        response = config_client.get(reverse('category-distribution'))

        assert response.status_code == status.HTTP_200_OK


class TestDeviceTotalView(BaseViewTest):
    def test_device_total(self, config_client: APIClient):
        response = config_client.get(reverse('device-total')).json()

        assert response['count'] == Device.objects.count()


class TestAssetsIPView(BaseViewTest):
    def test_device_total(self, config_client: APIClient):
        response = config_client.get(reverse('ip-distribution'))

        assert response.status_code == status.HTTP_200_OK


class TestRiskDeviceTop5(BaseViewTest):
    def test_risk_device(self, config_client: APIClient):
        """
        风险资产TOP5，安全事件+安全威胁最多的5个资产
        """
        device = DeviceFactory.create_batch_normal(6)
        for i in range(len(device)):
            DeviceAllAlertFactory.create_batch(5*i, device=device[i])
            SecurityEventFactory.create_batch(5*i, device=device[i])
        response = config_client.get(reverse('risk-device-top-5')).json()

        assert response['data'] == [
            {'ip': device[-1].ip, 'count': 50, 'percent': 100},
            {'ip': device[-2].ip, 'count': 40, 'percent': 80},
            {'ip': device[-3].ip, 'count': 30, 'percent': 60},
            {'ip': device[-4].ip, 'count': 20, 'percent': 40},
            {'ip': device[-5].ip, 'count': 10, 'percent': 20},
        ]


class TestExternalIPTop5(BaseViewTest):
    def test_external_ip(self, config_client: APIClient):
        """
        协议审计过来的外网IP最多5个
        """
        external = TodayExternalIP(timezone.now())
        external.clean()
        external._data = {'192.168.1.1': 10, '192.168.1.2': 8, '192.168.1.4': 6,
                          '192.168.1.5': 4, '192.168.1.6': 2, '192.168.1.7': 1}
        external.save()
        data = external.get_top_n()
        for d in data:
            d['percent'] = safe_divide(d['count'] * 100, 10)
        response = config_client.get(reverse('external-ip-top-5')).json()
        assert response['data'] == data
