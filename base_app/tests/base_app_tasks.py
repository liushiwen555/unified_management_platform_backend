import pytest
from requests.exceptions import RequestException

from base_app.tasks import device_heartbeat_task, batch_apply_strategies_task, \
    apply_strategies_task
from base_app.models import Device
from base_app.factory_data import DeviceFactory


# 测试celery暂时没有好的办法
@pytest.fixture(scope='session')
def celery_config():
    return {
        'broker_url': 'redis://localhost:6379/1',
        'result_backend': 'redis://localhost:6379/1'
    }


@pytest.mark.django_db
class TestBaseAppTasks(object):
    @pytest.fixture(scope='class')
    def device(self):
        device_ = DeviceFactory.create(
            strategy_apply_status=Device.STRATEGY_APPLY_STATUS_UN_APPLIED)
        return device_

    @pytest.fixture(scope='function')
    def auditor_device(self):
        """
        创建测试用审计设备，因为不涉及设备删除，只需要class级别创建一个就好
        """
        device_ = DeviceFactory.create(
            category=Device.CATEGORY_Security,
            type=Device.AUDITOR,
            strategy_apply_status=Device.STRATEGY_APPLY_STATUS_UN_APPLIED
        )
        return device_

    @pytest.fixture(scope='function')
    def firewall_device(self):
        """
        创建测试用防火墙设备，因为不涉及设备删除，只需要class级别创建一个就好
        """
        device_ = DeviceFactory.create(
            category=Device.CATEGORY_Security,
            type=Device.FIRE_WALL,
            strategy_apply_status=Device.STRATEGY_APPLY_STATUS_UN_APPLIED
        )
        return device_

    def test_batch_apply_strategies_task(self, celery_config, device):
        batch_apply_strategies_task([device.id])

    def test_device_heartbeat_task_not_registered(self, auditor_device: Device, firewall_device: Device):
        device_heartbeat_task()

        assert Device.objects.get(id=auditor_device.id).status == Device.NOT_REGISTERED
        assert Device.objects.get(id=firewall_device.id).status == Device.NOT_REGISTERED

    def test_device_heartbeat_task_offline(self, auditor_device: Device, firewall_device: Device):
        firewall_device.ip = '127.0.0.1'
        auditor_device.ip = '10.0.17.79'
        firewall_device.save()
        auditor_device.save()

        device_heartbeat_task()

        assert Device.objects.get(id=auditor_device.id).status == Device.OFFLINE
        assert Device.objects.get(id=firewall_device.id).status == Device.OFFLINE

    @pytest.mark.skip
    def test_apply_strategies_task(self, auditor_device: Device, firewall_device: Device):
        # 由于暂时没有可用于测试审计、防火墙设备，测试用设备都是伪造的信息，所以这里
        # 保留报错的捕获
        with pytest.raises(RequestException):
            apply_strategies_task(auditor_device.id)

        with pytest.raises(RequestException):
            apply_strategies_task(firewall_device.id)

