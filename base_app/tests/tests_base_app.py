import random
from typing import List

import pytest
import factory
from faker import Faker
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework import status
from django.db.models.signals import post_save

from base_app.models import Device, DeviceMonitorSetting, BaseStrategy
from base_app.factory_data import DeviceFactory, TemplateFactory
from firewall.models import BaseFirewallStrategy
from firewall.factory_data import BaseFirewallStrategyFactory
from auditor.factory_data import AuditWhiteListStrategyFactory
from auditor.models import AuditWhiteListStrategy
from utils.base_testcase import MyBaseTest, BaseUser
from utils.context import temporary_disconnect_signal
from base_app.signals import device_post_save
from base_app.serializers import DeviceUpdateSerializer
from base_app.views import check_or_update_device_strategy_apply_status
from utils.core.exceptions import CustomError

fake = Faker()
User = get_user_model()


@pytest.mark.django_db
def test_check_device_strategy_apply_status():
    with temporary_disconnect_signal(post_save, device_post_save, Device):
        device = DeviceFactory.create(
            strategy_apply_status=Device.STRATEGY_APPLY_STATUS_APPLYING)

    with pytest.raises(CustomError):
        check_or_update_device_strategy_apply_status(device)

    device = DeviceFactory.create(
        strategy_apply_status=Device.STRATEGY_APPLY_STATUS_APPLIED)
    check_or_update_device_strategy_apply_status(device)

    device = Device.objects.get(id=device.id)
    assert device.strategy_apply_status == Device.STRATEGY_APPLY_STATUS_UN_APPLIED


# @pytest.mark.skip
class TestDevice(TestCase):
    def test_create_device(self):
        device = DeviceFactory(
            strategy_apply_status=Device.STRATEGY_APPLY_STATUS_UN_APPLIED)
        device.save()

        assert device.id is not None

    def test_delete_device(self):
        device = DeviceFactory(strategy_apply_status=1)
        device.save()

        device.delete()

        assert Device.objects.filter(name=device.name).exists() is False

    def test_bulk_create_device(self):
        with temporary_disconnect_signal(post_save, device_post_save, Device):
            devices = DeviceFactory.create_batch(20)

        assert len(devices) == 20

    def test_save_device_with_no_register_code(self):
        device = DeviceFactory(register_code=None, type=Device.FIRE_WALL,
                               strategy_apply_status=1)

        device.save()

        assert device.id is not None
        assert device.register_code is not None


# @pytest.mark.skip
class TestDeviceMonitorSetting(TestCase):
    def test_create_monitor_setting(self):
        setting = DeviceMonitorSetting()
        setting.save()

        assert setting.id is not None

    def test_delete_monitor_setting(self):
        setting = DeviceMonitorSetting()
        setting.save()
        setting.delete()

        assert DeviceMonitorSetting.objects.exists() is False

    def test_raise_validator_error(self):
        setting = DeviceMonitorSetting(security_cpu_alert_percent=11)
        with pytest.raises(ValidationError):
            setting.full_clean()

        setting = DeviceMonitorSetting(security_cpu_alert_percent=101)
        with pytest.raises(ValidationError):
            setting.full_clean()

    def test_raise_repeated_error(self):
        setting = DeviceMonitorSetting()
        setting.save()

        setting = DeviceMonitorSetting()
        with pytest.raises(DRFValidationError):
            setting.save()


# @pytest.mark.skip
class TestBaseStrategy(TestCase):
    template = None
    device = None
    auditor = None
    FIREWALL_NUM = 20
    AUDITOR_NUM = 30

    def setUp(self) -> None:
        self.firewall_template = TemplateFactory.create()
        self.auditor_template = TemplateFactory.create()
        self.firewall = DeviceFactory.create(type=Device.FIRE_WALL,
                                             strategy_apply_status=1)
        self.auditor = DeviceFactory.create(type=Device.AUDITOR,
                                            strategy_apply_status=1)

    def test_dev_to_tmp(self):
        BaseFirewallStrategyFactory.create_batch(
            self.FIREWALL_NUM, device=self.firewall)
        AuditWhiteListStrategyFactory.create_batch(
            self.AUDITOR_NUM, device=self.auditor, template=None)

        BaseStrategy.dev_to_temp(self.firewall.id, self.firewall_template.id,
                                 Device.FIRE_WALL)
        assert BaseFirewallStrategy.objects.filter(
            template=self.firewall_template).count() == self.FIREWALL_NUM

        BaseStrategy.dev_to_temp(self.auditor.id, self.auditor_template.id,
                                 Device.AUDITOR)
        assert AuditWhiteListStrategy.objects.filter(
            template=self.auditor_template).count() == self.AUDITOR_NUM

    def test_temp_to_dev(self):
        BaseFirewallStrategyFactory.create_batch(self.FIREWALL_NUM,
                                                 template=self.firewall_template)
        AuditWhiteListStrategyFactory.create_batch(self.AUDITOR_NUM,
                                                   template=self.auditor_template)

        firewall = DeviceFactory.create(type=Device.FIRE_WALL,
                                        strategy_apply_status=1)
        BaseStrategy.temp_to_dev(firewall.id, self.firewall_template.id,
                                 Device.FIRE_WALL)

        assert BaseFirewallStrategy.objects.filter(
            device=firewall).count() == self.FIREWALL_NUM

        auditor = DeviceFactory.create(type=Device.AUDITOR,
                                       strategy_apply_status=1)
        BaseStrategy.temp_to_dev(auditor.id, self.auditor_template.id,
                                 Device.AUDITOR)
        assert AuditWhiteListStrategy.objects.filter(
            device=auditor).count() == self.AUDITOR_NUM

    def test_temp_to_temp(self):
        BaseFirewallStrategyFactory.create_batch(
            self.FIREWALL_NUM, template=self.firewall_template,
            device=Device.objects.filter(type=Device.FIRE_WALL).first()
        )
        AuditWhiteListStrategyFactory.create_batch(
            self.AUDITOR_NUM, template=self.auditor_template,
            device=Device.objects.filter(type=Device.AUDITOR).first()
        )

        self.new_firewall_temp = TemplateFactory.create(type=Device.FIRE_WALL)
        self.new_auditor_temp = TemplateFactory.create(type=Device.AUDITOR)

        BaseStrategy.temp_to_temp(self.firewall_template.id,
                                  self.new_firewall_temp.id,
                                  Device.FIRE_WALL)
        BaseStrategy.temp_to_temp(self.auditor_template.id,
                                  self.new_auditor_temp.id,
                                  Device.AUDITOR)
        assert BaseFirewallStrategy.objects.filter(
            template=self.new_firewall_temp).count() == self.FIREWALL_NUM
        assert AuditWhiteListStrategy.objects.filter(
            template=self.new_auditor_temp).count() == self.AUDITOR_NUM

    def test_del_dev_strategies(self):
        BaseFirewallStrategyFactory.create_batch(self.FIREWALL_NUM,
                                                 device=self.firewall)
        AuditWhiteListStrategyFactory.create_batch(self.AUDITOR_NUM,
                                                   device=self.auditor)

        assert BaseFirewallStrategy.objects.count() == self.FIREWALL_NUM
        assert AuditWhiteListStrategy.objects.count() == self.AUDITOR_NUM

        BaseStrategy.del_dev_strategies(self.firewall.id, Device.FIRE_WALL)
        BaseStrategy.del_dev_strategies(self.auditor.id, Device.AUDITOR)

        assert BaseFirewallStrategy.objects.count() == 0
        assert AuditWhiteListStrategy.objects.count() == 0


basic_parameters = pytest.mark.parametrize('user, expect_code', [
    (None, status.HTTP_401_UNAUTHORIZED),
    (BaseUser.admin_name, status.HTTP_200_OK),
    (BaseUser.auditor_name, status.HTTP_200_OK),
    (BaseUser.engineer_name, status.HTTP_200_OK),
    (BaseUser.config_engineer_name, status.HTTP_200_OK),
])

basic_permission = [
    (None, status.HTTP_401_UNAUTHORIZED),
    (BaseUser.admin_name, status.HTTP_403_FORBIDDEN),
    (BaseUser.auditor_name, status.HTTP_403_FORBIDDEN),
    (BaseUser.engineer_name, status.HTTP_403_FORBIDDEN),
]

config_engineer_permission = pytest.mark.parametrize('user, expect_code', [
    *basic_permission,
    (BaseUser.config_engineer_name, status.HTTP_200_OK),
])

config_engineer_create = pytest.mark.parametrize('user, expect_code', [
    *basic_permission,
    (BaseUser.config_engineer_name, status.HTTP_201_CREATED),
])

config_engineer_delete = pytest.mark.parametrize('user, expect_code', [
    *basic_permission,
    (BaseUser.config_engineer_name, status.HTTP_204_NO_CONTENT),
])


# @pytest.mark.skip
@pytest.mark.django_db
class TestDeviceView(MyBaseTest):
    @pytest.fixture(scope='class')
    def set_up(self):
        with temporary_disconnect_signal(post_save, device_post_save, Device):
            DeviceFactory.create_batch(20, category=1,
                                       type=factory.LazyFunction(
                                           lambda: random.choice(
                                               [Device.FIRE_WALL,
                                                Device.AUDITOR])))
            DeviceFactory.create_batch(20, category=2, type=7)
        self.default_user = User.objects.get(username=BaseUser.auditor_name)
        self.client.force_authenticate(self.default_user)

    @pytest.fixture(scope='function')
    def device(self):
        device_ = DeviceFactory.create(strategy_apply_status=1)
        return device_

    @pytest.fixture(scope='function')
    def devices(self):
        devices_ = DeviceFactory.create_batch(20, strategy_apply_status=1)
        return devices_

    @pytest.fixture(scope='function')
    def config_engineer(self):
        self.client.force_authenticate(User.objects.get(
            username=BaseUser.config_engineer_name))

    @basic_parameters
    def test_device_list_permission(self, user: str, expect_code: int):
        """
        /base/device/
        """
        if user:
            user = User.objects.get(username=user)
        self.client.force_authenticate(user)

        url = reverse('device-manage-list')
        response = self.client.get(url)
        assert response.status_code == expect_code

    @pytest.mark.parametrize('category, type_', [
        ('1', '2'), ('2', None), (None, '7')
    ])
    def test_device_list(self, category: str, type_: str, set_up):
        """
        /base/device/
        """
        url = reverse('device-manage-list')
        response = self.client.get(url,
                                   data={'category': category, 'type': type_})

        devices_count = response.data['count']

        assert response.status_code == status.HTTP_200_OK
        if not type_:
            assert devices_count == Device.objects.filter(
                category=int(category), type__in=[0, 7, 8]).count()
        if not category:
            assert devices_count == Device.objects.filter(
                category=2, type=7).count()
        if type_ and category:
            assert devices_count == Device.objects.filter(
                category=1, type=2).count()

    @config_engineer_create
    def test_device_post(self, user: str, expect_code: int):
        """
        /base/device/
        """
        if user:
            user = User.objects.get(username=user)
        self.client.force_authenticate(user=user)
        response = self.client.post(
            reverse('device-manage-list'),
            data={
                'name': 'test',
                'category': Device.CATEGORY_Security,
                'type': Device.FIRE_WALL,
                'ip': fake.ipv4(),
                'mac': fake.mac_address().upper(),
            }
        )

        assert response.status_code == expect_code

        if response.status_code == status.HTTP_201_CREATED:
            assert Device.objects.filter(name='test').exists()

    @config_engineer_permission
    def test_update_device(self, user: str, expect_code: int, device: Device):
        """
        PUT /base/device/{id}/
        """
        if user:
            user = User.objects.get(username=user)
        self.client.force_authenticate(user=user)

        device.ip = fake.ipv4()
        device.mac = fake.mac_address()
        device.ip_mac_bond = False

        response = self.client.put(
            reverse('device-manage-detail', args=(device.id,)),
            data=dict(DeviceUpdateSerializer(device).data)
        )

        assert response.status_code == expect_code
        if response.status_code == status.HTTP_200_OK:
            assert Device.objects.filter(ip=device.ip, mac=device.mac,
                                         ip_mac_bond=False).exists()

    @basic_parameters
    def test_get_device(self, user: str, expect_code: int, device: Device):
        """
        GET /base/device/{id}/
        """
        if user:
            user = User.objects.get(username=user)
        self.client.force_authenticate(user=user)

        response = self.client.get(
            reverse('device-manage-detail', args=(device.id,)),
        )

        assert response.status_code == expect_code

    @config_engineer_delete
    def test_delete_device(self, user: str, expect_code: int, device: Device):
        """
        DELETE /base/device/{id}/
        """
        if user:
            user = User.objects.get(username=user)
        self.client.force_authenticate(user=user)

        response = self.client.delete(
            reverse('device-manage-detail', args=(device.id,)),
        )

        assert response.status_code == expect_code

        if response.status_code == status.HTTP_204_NO_CONTENT:
            with pytest.raises(Device.DoesNotExist):
                Device.objects.get(id=device.id)


@pytest.mark.django_db
class TestDeviceMonitorThresholdView(MyBaseTest):
    @pytest.fixture(scope='class')
    def default_client(self):
        self.default_user = User.objects.get(username=BaseUser.auditor_name)
        self.client.force_authenticate(self.default_user)

    @pytest.fixture(scope='class')
    def device_monitor_setting(self):
        """
        设备监控设置只能存在一条，所以scope是class就够用了
        """
        setting = DeviceMonitorSetting()
        setting.save()

        return setting

    def test_dev_monitor_threshold_get(self, device_monitor_setting,
                                       default_client):
        """
        GET /base/device/dev_monitor_threshold
        """
        response = self.client.get(
            reverse('dev_monitor_threshold'),
        )

        assert response.status_code == status.HTTP_200_OK

    @config_engineer_permission
    def test_dev_monitor_threshold_patch(self, user, expect_code,
                                         device_monitor_setting,
                                         default_client):
        """
        PATH /base/device/dev_monitor_threshold
        """
        if user:
            user = User.objects.get(username=user)
        self.client.force_authenticate(user=user)

        response = self.client.patch(
            reverse('dev_monitor_threshold'),
            data={
                'security_cpu_alert_percent': random.randint(60, 80),
                'security_memory_alert_percent': random.randint(60, 80)
            }
        )

        assert response.status_code == expect_code

        if response.status_code == status.HTTP_200_OK:
            response = self.client.patch(
                reverse('dev_monitor_threshold'),
                data={
                    'security_cpu_alert_percent': random.randint(0, 10),
                    'security_memory_alert_percent': random.randint(60, 80)
                }
            )
            assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestDeviceMonitorFrequencyView(MyBaseTest):
    @pytest.fixture(scope='class')
    def default_client(self):
        self.default_user = User.objects.get(username=BaseUser.auditor_name)
        self.client.force_authenticate(self.default_user)

    @pytest.fixture(scope='class')
    def device_monitor_setting(self):
        """
        设备监控设置只能存在一条，所以scope是class就够用了
        """
        setting = DeviceMonitorSetting()
        setting.save()

        return setting

    def test_dev_monitor_frequency_get(self, device_monitor_setting,
                                       default_client):
        """
        GET /base/device/dev_monitor_frequency
        """
        response = self.client.get(
            reverse('dev_monitor_frequency'),
        )

        assert response.status_code == status.HTTP_200_OK

    @config_engineer_permission
    def test_dev_monitor_frequency_patch(self, user, expect_code,
                                         device_monitor_setting,
                                         default_client):
        """
        PATH /base/device/dev_monitor_frequency
        """
        if user:
            user = User.objects.get(username=user)
        self.client.force_authenticate(user=user)

        response = self.client.patch(
            reverse('dev_monitor_frequency'),
            data={
                'security_monitor_period': random.randint(60, 80),
                'communication_monitor_period': random.randint(60, 80)
            }
        )

        assert response.status_code == expect_code
