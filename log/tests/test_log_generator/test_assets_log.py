import os
from typing import Dict, List

import pytest
from django.conf import settings
from django.urls import reverse
from django.utils.http import urlencode
from faker import Faker
from rest_framework.test import APIClient

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from log.models import UnifiedForumLog, SecurityEvent
from log.security_event import AssetsEventLog
from log.tests.test_log_generator.base_testcase import BaseLogTest

fake = Faker()


class TestAssetsLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    UPDATE_DEVICE = 'device-manage-detail'
    POST_DEVICE = 'device-manage-list'

    def format_content(self, method: str, id: int, name: str, status_code: int):
        return f'{method}【{id} - {name}】, {self.status_desc(status_code)}'

    @pytest.fixture(scope='class')
    def data(self):
        _data = dict(
            brand='', category=Device.CATEGORY_Security, created_at='',
            description='', hardware='', ip=fake.ipv4(), ip_mac_bond=False,
            location='', mac=fake.mac_address(), monitor=True,
            name=fake.text(max_nb_chars=10), register_cide='',
            responsible_user='', type=Device.AUDITOR, value=1
        )
        return _data

    def test_add_device(self, config_client: APIClient, data: Dict):
        response = config_client.post(
            reverse(self.POST_DEVICE),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '添加', response.data['id'], response.data['name'],
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_delete_device(self, config_client: APIClient):
        device = DeviceFactory.create(
            strategy_apply_status=Device.STRATEGY_APPLY_STATUS_UN_APPLIED)

        response = config_client.delete(
            reverse(self.UPDATE_DEVICE, args=(device.id,))
        )

        content = self.format_content(
            '删除', device.id, device.name, response.status_code
        )
        log = UnifiedForumLog.objects.filter(content=content)

        assert log.exists()
        self.check_type_and_category(log[0])

        assert AssetsEventLog.get_queryset(content='删除 【{id}-{name}】'.format(
            id=device.id, name=device.name,
        )).exists()

    def test_update_device(self, config_client: APIClient, data: Dict):
        device = DeviceFactory.create(
            strategy_apply_status=Device.STRATEGY_APPLY_STATUS_UN_APPLIED)

        response = config_client.put(
            reverse(self.UPDATE_DEVICE, args=(device.id,)),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '编辑', device.id, data['name'], response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestAssetsStatusLog(BaseLogTest):
    """
    批量修改指定id的资产的状态
    """
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    UPDATE_URL = 'device-batch'

    content_template = {
        'ip_mac_bond': ('批量编辑【{id} - {name}】等{count}个资产IP/MAC绑定为{status},'
                        ' {result}'),
        'monitor': ('批量编辑【{id} - {name}】等{count}个资产性能监控为{status},'
                    ' {result}'),
        'log_status': ('批量编辑【{id} - {name}】等{count}个资产日志监控为{status},'
                       ' {result}'),
        'responsible_user': ('批量编辑【{id} - {name}】等{count}个资产安全负责人为'
                             '{status}, {result}'),
        'location': ('批量编辑【{id} - {name}】等{count}个资产位置为{status},'
                     ' {result}'),
        'value': ('批量编辑【{id} - {name}】等{count}个资产重要程度为{status},'
                  ' {result}'),
        'ip_mac_bond_single': '{status}了【{id} - {name}】IP/MAC绑定, {result}',
        'monitor_single': '{status}了【{id} - {name}】性能监控, {result}',
        'log_status_single': '{status}了【{id} - {name}】日志监控, {result}',
    }

    @pytest.fixture(scope='function')
    def device(self) -> List[Device]:
        return DeviceFactory.create_batch_normal(2)

    def format_content(self, target: str, id: int, name: str, count: int,
                       status: str, status_code: int):
        content = self.content_template[target].format(
            id=id, name=name, count=count, status=status,
            result=self.status_desc(status_code)
        )
        return content

    def test_ip_mac_bond(self, config_client: APIClient, device: List[Device]):
        data = dict(
            ids=[d.id for d in device],
            ip_mac_bond=True,
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'ip_mac_bond', device[0].id, device[0].name, len(device), '启用',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_ip_mac_bond_single(self, config_client: APIClient,
                                device: List[Device]):
        device = device[0]

        data = dict(
            ids=[device.id],
            ip_mac_bond=True
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json',
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'ip_mac_bond_single', device.id, device.name, 1, '启用',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_log_status(self, config_client: APIClient, device: List[Device]):
        data = dict(
            ids=[d.id for d in device],
            log_status=True,
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'log_status', device[0].id, device[0].name, len(device), '启用',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_log_status_single(self, config_client: APIClient,
                               device: List[Device]):
        device = device[0]

        data = dict(
            ids=[device.id],
            log_status=True
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json',
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'log_status_single', device.id, device.name, 1, '启用',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_monitor(self, config_client: APIClient,
                     device: List[Device]):
        data = dict(
            ids=[d.id for d in device],
            monitor=True,
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'monitor', device[0].id, device[0].name, len(device), '启用',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_monitor_single(self, config_client: APIClient,
                            device: List[Device]):
        device = device[0]

        data = dict(
            ids=[device.id],
            monitor=True
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json',
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'monitor_single', device.id, device.name, 1, '启用',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_responsible_user(self, config_client: APIClient,
                              device: List[Device]):
        data = dict(
            ids=[d.id for d in device],
            responsible_user='123',
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'responsible_user', device[0].id, device[0].name, len(device),
            '123',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_location(self, config_client: APIClient, device: List[Device]):
        data = dict(
            ids=[d.id for d in device],
            location='123',
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'location', device[0].id, device[0].name, len(device), '123',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_value(self, config_client: APIClient, device: List[Device]):
        data = dict(
            ids=[d.id for d in device],
            value=1
        )
        response = config_client.put(
            reverse(self.UPDATE_URL),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'value', device[0].id, device[0].name, len(device), '低',
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestAssetsBatchDeleteLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    UPDATE_URL = 'device-batch'

    def format_content(self, id: int, name: str, count: int,
                       status_code: int):
        content = '批量删除【{id} - {name}】等{count}个资产, {result}'.format(
            id=id, name=name, count=count,
            result=self.status_desc(status_code)
        )
        return content

    def test_delete_assets(self, config_client: APIClient):
        devices = DeviceFactory.create_batch_normal(10)
        dev_ids = [d.id for d in devices]
        url = reverse('device-batch') \
              + '?' + '&'.join([f'id={d}' for d in dev_ids])
        response = config_client.delete(url)

        log = UnifiedForumLog.objects.filter(
            content=self.format_content(devices[0].id, devices[0].name,
                                        10, response.status_code)
        )
        assert log.exists()
        self.check_type_and_category(log[0])


class TestAllAssetsStatusLog(BaseLogTest):
    """
    批量修改给给定筛选条件的资产的状态
    """
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    UPDATE_URL = 'device-api'

    query = {'category': '1', 'name': '123'}
    content_template = {
        'ip_mac_bond': ('批量编辑【{id} - {name}】等{count}个资产IP/MAC绑定为{status},'
                        ' {result}'),
        'monitor': ('批量编辑【{id} - {name}】等{count}个资产性能监控为{status},'
                    ' {result}'),
        'responsible_user': ('批量编辑【{id} - {name}】等{count}个资产安全负责人为'
                             '{status}, {result}'),
        'location': ('批量编辑【{id} - {name}】等{count}个资产位置为{status},'
                     ' {result}'),
    }

    def format_content(self, target: str, id: int, name: str, count: int,
                       status: str, status_code: int):
        content = self.content_template[target].format(
            target=target, id=id, name=name, count=count, status=status,
            result=self.status_desc(status_code)
        )
        return content

    @pytest.fixture(scope='function')
    def device(self) -> Device:
        return DeviceFactory.create_normal(category=1, name='123')

    def test_ip_mac_bond(self, config_client: APIClient, device: Device):
        url = reverse(self.UPDATE_URL) + '?{}'.format(urlencode(self.query))
        response = config_client.put(
            url,
            data=dict(ip_mac_bond=True),
            format='json'
        )
        devices = Device.objects.filter(category=1, name='123')
        device = devices.first()
        count = devices.count()
        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'ip_mac_bond', device.id, device.name, count, '启用', response.status_code,
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_monitor(self, config_client: APIClient, device: Device):
        url = reverse(self.UPDATE_URL) + '?{}'.format(urlencode(self.query))
        response = config_client.put(
            url,
            data=dict(monitor=True),
            format='json'
        )

        devices = Device.objects.filter(category=1, name='123')
        device = devices.first()
        count = devices.count()
        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'monitor', device.id, device.name, count, '启用',
            response.status_code,
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_responsible_user(self, config_client: APIClient, device: Device):
        url = reverse(self.UPDATE_URL) + '?{}'.format(urlencode(self.query))
        response = config_client.put(
            url,
            data=dict(responsible_user='123'),
            format='json'
        )

        devices = Device.objects.filter(category=1, name='123')
        device = devices.first()
        count = devices.count()
        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'responsible_user', device.id, device.name, count, '123',
            response.status_code,
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_location(self, config_client: APIClient, device: Device):
        url = reverse(self.UPDATE_URL) + '?{}'.format(urlencode(self.query))
        response = config_client.put(
            url,
            data=dict(location='123'),
            format='json'
        )

        devices = Device.objects.filter(category=1, name='123')

        device = devices.first()
        count = devices.count()

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            'location', device.id, device.name, count, '123',
            response.status_code,
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestDeviceExportLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    EXPORT_URL = 'export-device'

    def format_content(self, id: int, name: str, count: int, status_code: int):
        return f'批量导出【{id} - {name}】等{count}个资产, ' \
               f'{self.status_desc(status_code)}'

    def test_export(self, config_client: APIClient):
        devices = Device.objects.all()
        data = dict(
            dev_ids=[d.id for d in devices],
        )
        response = config_client.get(
            reverse(self.EXPORT_URL),
            data=data,
        )
        log = UnifiedForumLog.objects.filter(content=self.format_content(
            devices[0].id, devices[0].name, len(devices), response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestAllDeviceExportLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    EXPORT_URL = 'export-all-device'

    def format_content(self, id: int, name: str, count: int, status_code: int):
        return f'批量导出【{id} - {name}】等{count}个资产,' \
               f' {self.status_desc(status_code)}'

    @pytest.fixture(scope='function')
    def device(self) -> Device:
        return DeviceFactory.create_normal(category=1, name='123')

    def test_export(self, config_client: APIClient, device: Device):
        query = {'category': '1', 'name': '123'}
        response = config_client.get(
            reverse(self.EXPORT_URL),
            data=query,
            format='json',
        )
        log = UnifiedForumLog.objects.filter(
            content=self.format_content(device.id, device.name, 1,
                                        response.status_code))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestDeviceImportLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    IMPORT_URL = 'device-batch'

    def format_content(self, id: int, name: str, count: int, status_code: int):
        return f'批量导入【{id} - {name}】等{count}个资产, {self.status_desc(status_code)}'

    def test_import(self, config_client: APIClient):
        data = [
            {
                "name": "测试测试3",
                "category": 2,
                "type": 8,
                "brand": "华为",
                "hardware": "X60",
                "ip": "192.168.1.2",
                "mac": "11:22:33:44:33:99",
                "responsible_user": "谱久村11111",
                "location": "麻布十番",
                "value": 3,
                "description": "",
                "error": "",
                "valid": True,
            },
        ]
        response = config_client.post(
            reverse(self.IMPORT_URL),
            data={'data': data},
            format='json'
        )
        device = Device.objects.get(name=response.data[0]['name'])
        log = UnifiedForumLog.objects.filter(content=self.format_content(
            device.id, device.name, len(response.data), response.status_code
        ))
        assert log.exists()
        self.check_type_and_category(log[0])
