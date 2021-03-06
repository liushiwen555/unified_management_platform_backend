from os import path
from typing import Dict

import pytest
from django.conf import settings
from django.db.models import Q
from django.urls import reverse
from django.utils.http import urlencode
from faker import Faker
from rest_framework import status
from rest_framework.test import APIClient

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from snmp.factory_data import SNMPSettingFactory, SNMPTemplateFactory, \
    SNMPRuleFactory
from unified_log.factory_data import LogProcessTemplateFactory
from utils.base_testcase import BaseViewTest, ConfigEngineerPermission
from utils.core.exceptions import CustomError

fake = Faker()


@pytest.mark.django_db
class TestDeviceViewPermission(BaseViewTest):
    @ConfigEngineerPermission.authenticate_read_only
    def test_read_permissions(self, all_client: Dict[str, APIClient], user: str,
                              expect_code: int):
        client = all_client[user]
        target = ['export-device-template', 'category-device-list']

        for i in target:
            url = reverse(i)
            response = client.get(url)

            assert response.status_code == expect_code

    @ConfigEngineerPermission.config_engineer_permission_200
    def test_update_permissions(self, all_client: Dict[str, APIClient],
                                user: str, expect_code: int):
        client = all_client[user]
        devices = DeviceFactory.create_batch_normal(10)
        dev_ids = [d.id for d in devices]
        targets = []
        body = []

        for i in range(len(targets)):
            url = reverse(targets[i])
            response = client.put(url, data=body[i], format='json')
            assert response.status_code == expect_code

    @ConfigEngineerPermission.config_engineer_permission_201
    def test_create_permissions(self, all_client: Dict[str, APIClient],
                                user: str,
                                expect_code: int):
        client = all_client[user]

        data = dict(
            name='dddd', brand='1234', hardware='1234', category=1, type=1,
            ip='192.168.0.1', mac='11:22:33:44:55:77', version='V1',
            monitor=True, log_status=True
        )

        response = client.post(
            reverse('device-manage-list'),
            data=data,
            format='json',
        )
        assert response.status_code == expect_code

    @ConfigEngineerPermission.config_engineer_permission_204
    def test_delete_permissions(self, all_client: Dict[str, APIClient],
                                user: str, expect_code: int):
        client = all_client[user]
        device1 = DeviceFactory.create_normal()
        devices = DeviceFactory.create_batch_normal(2)

        url1 = reverse('device-manage-detail', args=(device1.id,))
        response = client.delete(url1)
        assert response.status_code == expect_code
        url2 = reverse('device-batch') \
               + '?' + '&'.join([f'id={d.id}' for d in devices])
        response = client.delete(url2)
        assert response.status_code == expect_code


@pytest.mark.django_db
class TestDeviceView(BaseViewTest):
    def test_create_device(self, config_client: APIClient):
        data = dict(
            name='dddd', brand='1234', hardware='1234', category=1, type=1,
            ip='192.168.0.1', mac='11:22:33:44:55:77', version='V1',
            monitor=True, log_status=True
        )

        response = config_client.post(
            reverse('device-manage-list'),
            data=data,
            format='json',
        )

        device = Device.objects.get(id=response.data['id'])
        assert response.status_code == status.HTTP_201_CREATED
        for k, v in data.items():
            assert v == getattr(device, k)

    @pytest.mark.parametrize('ip, mac, error',
                             [('127.1.1.1', '11:22:33:44:55:88',
                               CustomError.IP_REPEAT_ERROR),
                              ('127.1.1.0', '11:22:33:44:55:77',
                               CustomError.MAC_REPEAT_ERROR)])
    def test_repeated_ip_and_mac(self, config_client: APIClient, ip: str,
                                 mac: str, error: int):
        DeviceFactory.create_normal(ip=ip, mac=mac)

        response = config_client.post(
            reverse('device-manage-list'),
            data=dict(
                name='dddd', category=1, type=1, ip='127.1.1.1',
                mac='11:22:33:44:55:77')
        )

        assert response.data['detail'] == CustomError(error_code=error
                                                      ).detail['detail']


    def test_category_device_list_1(self, config_client: APIClient):
        """
        ????????????????????????????????????????????????????????????????????????????????????
        """
        DeviceFactory.create_batch_normal(10, category=1, type=2)
        DeviceFactory.create_batch_normal(10, category=1, type=1)
        DeviceFactory.create_batch_normal(10, category=1, type=0)

        DeviceFactory.create_batch_normal(10, category=2, type=7)
        DeviceFactory.create_batch_normal(10, category=2, type=0)

        response = config_client.get(
            reverse('category-device-list'),
            data=dict(
                category=1,
                type=2,
            )
        )
        assert response.data['count'] == Device.objects.filter(
            category=1, type=2).count()

        response = config_client.get(
            reverse('category-device-list'),
            data=dict(
                category=1,
                type=0,
            )
        )
        assert response.data['count'] == Device.objects.filter(
            category=1, type=0).count()

    def test_category_device_list_2(self, config_client: APIClient):
        """
        ????????????????????????????????????????????????????????????????????????????????????
        """
        DeviceFactory.create_batch_normal(10, category=2, type=7)
        DeviceFactory.create_batch_normal(10, category=2, type=0)

        DeviceFactory.create_batch_normal(10, category=1, type=0)
        DeviceFactory.create_batch_normal(10, category=1, type=3)

        response = config_client.get(
            reverse('category-device-list'),
            data=dict(
                category=2,
            )
        )
        assert response.data['count'] == Device.objects.filter(
            category=2, type__in=[0, 7, 8]).count()

    def test_category_device_list_filter(self, config_client: APIClient):
        """
        ???????????????????????????IP????????????????????????????????????????????????????????????????????????????????????????????????
        ??????????????????
        """
        rules = SNMPRuleFactory.create_batch(2)
        template = SNMPTemplateFactory.create(name='????????????', rules=rules)
        log_template = LogProcessTemplateFactory.create(name='????????????')
        device = DeviceFactory.create_normal(
            name='????????????', ip='127.0.0.1', log_status=True,
            log_template=log_template, monitor=True, category=1, type=1)
        setting = SNMPSettingFactory(template=template, device=device)

        response = config_client.get(
            reverse('category-device-list'),
            data=dict(
                name='????????????',
                ip='127.0.0.1',
                log_template='????????????',
                snmp_template='????????????',
                category=1,
                type=1,
                log_status=True,
                monitor=True,
            ),
            format='json'
        )
        d = Device.objects.get(name='????????????')
        assert response.data['count'] == 1

    def test_category_device_list_filter_no_response(
            self, config_client: APIClient):
        """
        ?????????????????????????????????????????????????????????????????????
        """
        DeviceFactory.create_batch_normal(10, category=1, type=1,
                                          monitor=True, log_status=False)
        DeviceFactory.create_batch_normal(10, category=1, type=1,
                                          monitor=False, log_status=True)
        response = config_client.get(
            reverse('category-device-list'),
            data=dict(
                category=1,
                type=1
            )
        )

        assert response.data['count'] == Device.objects.filter(
            category=1, type=1).filter(
            Q(monitor=True) | Q(log_status=True)).count()

    def test_bulk_update_device(self, config_client: APIClient):
        """
        ??????????????????id?????????
        ??????mac?????????????????????????????????ip???mac
        """
        devices = DeviceFactory.create_batch_normal(
            20, ip_mac_bond=False, monitor=False, log_status=False)

        dev_ids = [d.id for d in devices]

        response = config_client.put(
            reverse('device-batch'),
            data=dict(
                ids=dev_ids,
                ip_mac_bond=True,
                monitor=True,
                log_status=True,
                location='1234',
                responsible_user='2234'
            )
        )

        assert response.status_code == status.HTTP_200_OK
        assert 20 == Device.objects.filter(
            id__in=dev_ids, ip_mac_bond=True, monitor=True, log_status=True,
            location='1234', responsible_user='2234'
        ).count()

        # ????????????????????????id??????????????????
        dev_ids_copy = dev_ids.copy()
        dev_ids_copy[-1] = -1
        dev_ids_copy[-2] = -2

        response1 = config_client.put(
            reverse('device-batch'),
            data=dict(
                ids=dev_ids_copy,
                ip_mac_bond=False,
                monitor=False,
                log_status=False,
                location='1234',
                responsible_user='2234'
            )
        )

        assert response1.status_code == status.HTTP_200_OK
        assert 18 == Device.objects.filter(
            id__in=dev_ids, ip_mac_bond=False, monitor=False, log_status=False,
            location='1234', responsible_user='2234'
        ).count()

    def test_update_all_device(self, config_client: APIClient):
        """
        ???????????????????????????????????????????????????
        """
        DeviceFactory.create_batch_normal(20, category=1, type=2,
                                          ip_mac_bond=True,
                                          monitor=True)
        # ?????????
        DeviceFactory.create_batch_normal(20, category=2, type=3)

        queryset = Device.objects.filter(category=1, type=2, ip_mac_bond=True,
                                         monitor=True)
        count = queryset.count()

        # ???????????????????????????????????????????????????
        url = reverse('device-api') + '?{}'.format(
            urlencode({'category': 1, 'type': 2, 'ip_mac_bond': True,
                       'monitor': True})
        )
        response = config_client.put(
            url,
            data=dict(
                ip_mac_bond=False,
                monitor=False,
                log_status=False,
                location='1234',
                responsible_user='2234',
            )
        )

        assert response.status_code == status.HTTP_200_OK
        assert Device.objects.filter(
            monitor=False, ip_mac_bond=False, log_status=False,
            location='1234', responsible_user='2234'
        ).count() == count

    # @pytest.mark.skip
    def test_export_device(self, config_client: APIClient):
        response = config_client.get(
            reverse('export-device'),
            data={
                'id': [-1]
            },
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK

        devices = DeviceFactory.create_batch_normal(20)

        response = config_client.get(
            reverse('export-device'),
            data={
                'id': [d.id for d in devices]
            },
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK

    # @pytest.mark.skip
    def test_export_all_device(self, config_client: APIClient):
        DeviceFactory.create_batch_normal(20, category=1, type=2)
        response = config_client.get(
            reverse('export-all-device'),
            data={
                'category': 1,
                'type': 2,
            },
            foramt='json'
        )
        assert response.status_code == status.HTTP_200_OK

    def test_bulk_delete(self, config_client: APIClient):
        devices = DeviceFactory.create_batch_normal(10)
        dev_ids = [d.id for d in devices]

        url = reverse('device-batch') \
              + '?' + '&'.join([f'id={d}' for d in dev_ids])
        response = config_client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Device.objects.filter(id__in=dev_ids).exists()

    @ConfigEngineerPermission.config_engineer_permission_200
    def test_import_device_file(self, all_client: Dict[str, APIClient],
                                user: str, expect_code: int):
        client = all_client[user]
        with open(path.join(settings.MEDIA_ROOT, '????????????.xlsx'), 'rb') as f:
            response = client.post(
                reverse('device-manage-import-device-file'),
                {'file': f}, format='multipart'
            )
            assert response.status_code == expect_code
            if response.status_code == status.HTTP_200_OK:
                devices = response.data
                assert len(response.data) == 2
                assert response.data[0]['valid'] is False
                assert response.data[1]['valid']

    @ConfigEngineerPermission.config_engineer_permission_201
    def test_batch_device_post(self, all_client: Dict[str, APIClient],
                               user: str, expect_code: int):
        client = all_client[user]
        data = [
            {
                "name": "????????????3",
                "category": 2,
                "type": 8,
                "brand": "??????",
                "hardware": "X60",
                "ip": "192.168.1.2",
                "mac": "11:22:33:44:33:99",
                "responsible_user": "?????????11111",
                "location": "????????????",
                "value": 3,
                "description": "",
                "error": "",
                "valid": True,
            },
        ]

        response = client.post(
            reverse('device-batch'),
            data={'data': data},
            format='json'
        )
        assert response.status_code == expect_code
        if response.status_code == status.HTTP_201_CREATED:
            assert Device.objects.filter(name='????????????3').exists()
