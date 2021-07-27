from typing import List

import pytest
from rest_framework.test import APIClient
from django.urls import reverse

from user.models import User, Group, UserExtension
from setting.models import Setting
from utils.base_testcase import BaseViewTest, BaseUser
from log.security_event import *
from log.tasks import check_user_pwd_modified, device_offline_event
from setting.system_check import CPUCheck, MemoryCheck, DiskCheck
from base_app.factory_data import DeviceFactory, Device
from statistic.tasks import SystemRunningTask, MainViewTask
from statistic.models import SystemRunning
from statistic.factory_data import SystemRunningFactory, LogStatisticDayFactory
from log.factory_data import DeviceAllAlertFactory, SecurityEventFactory
from log.models import DeviceAllAlert
from snmp.snmp_run import SNMPClient
from snmp.factory_data import SNMPSettingFactory


@pytest.fixture(scope='class')
def group() -> Group:
    return Group.objects.first()


class TestPasswdErrorExceed(BaseViewTest):
    """
    测试因密码锁定账户达5个产生安全事件
    """

    @pytest.fixture(scope='function')
    def users(self, group) -> List[User]:
        username = 'test1'
        password = BaseUser.right_password

        result = []
        for i in range(6):
            result.append(
                User.objects.create_user(
                    username=username + str(i), password=password, group=group)
            )
        return result

    def test_password(self, client: APIClient, users: List[User]):
        setting, _ = Setting.objects.get_or_create(lockout_threshold=1)
        for i in range(4):
            client.post(
                reverse('user-login'),
                data={
                    'username': users[i].username,
                    'password': 'misaki123'
                },
                format='json'
            )
        assert not PasswordErrorExceedEvent.get_queryset().exists()

        # 超过5个登录失败需要有安全事件
        client.post(
            reverse('user-login'),
            data={
                'username': users[4].username,
                'password': 'misaki123'
            },
            format='json'
        )
        assert PasswordErrorExceedEvent.get_queryset(
            content='当天因密码错误锁定账户数达5个').exists()

        # 1小时内有不产生重复的事件
        client.post(
            reverse('user-login'),
            data={
                'username': users[4].username,
                'password': 'misaki123'
            },
            format='json'
        )
        assert PasswordErrorExceedEvent.get_queryset(
            content='当天因密码错误锁定账户数达5个').count() == 1


@pytest.mark.django_db
class TestUnModifiedPasswordEvent:
    def test_un_modified_password(self, group):
        for i in range(4):
            user = User.objects.create_user(
                username='Test' + str(i),
                password=BaseUser.right_password,
                group=group
            )
            user.un_modify_passwd = True
            user.save()
        check_user_pwd_modified()
        assert not UnModifiedPasswordEvent.get_queryset(
            content__contains='当前因密码使用天数达到阈值告警').exists()

        user = User.objects.create_user(
            username='Test5',
            password=BaseUser.right_password,
            group=group
        )
        user.un_modify_passwd = True
        user.save()
        check_user_pwd_modified()
        assert UnModifiedPasswordEvent.get_queryset(
            content__contains='当前因密码使用天数达到阈值告警').exists()


@pytest.mark.django_db
class TestAbnormalLoginEvent:
    @pytest.fixture(scope='function')
    def user(self, group) -> User:
        return User.objects.create_user(
            username='Login', password=BaseUser.right_password, group=group
        )

    @pytest.mark.parametrize('current', [datetime(2020, 10, 10, 21, 59),
                                         datetime(2020, 10, 10, 6, 1)])
    def test_normal_login(self, current, user):
        current = current.astimezone(tz=timezone.utc)
        event = AbnormalLoginEvent(user=user, current=current)
        event.generate()

        assert not AbnormalLoginEvent.get_queryset(
            content__contains='时间请求登录').exists()

    @pytest.mark.parametrize('current', [datetime(2020, 10, 10, 22, 00),
                                         datetime(2020, 10, 10, 6, 0)])
    def test_abnormal_login(self, current, user):
        current = current.astimezone(tz=timezone.utc)
        event = AbnormalLoginEvent(user=user, current=current)
        event.generate()

        assert AbnormalLoginEvent.get_queryset(
            content__contains='时间请求登录').exists()


@pytest.mark.django_db
class TestCPUEvent:
    def test_cpu_event(self):
        check = CPUCheck(80)
        check.generate_alarm()

        assert CPUEvent.get_queryset(content__contains='CPU使用率').exists()


@pytest.mark.django_db
class TestMemoryEvent:
    def test_memory_event(self):
        check = MemoryCheck(80)
        check.generate_alarm()

        assert MemoryEvent.get_queryset(content__contains='内存使用率').exists()


@pytest.mark.django_db
class TestAssetsOfflineEvent:
    def test_assets_offline(self):
        device = DeviceFactory.create_normal()
        device = Device.objects.get(id=device.id)
        device.status = Device.ONLINE
        device.save()

        device_offline_event(device)
        assert AssetsOfflineEvent.get_queryset(content='资产离线').exists()


@pytest.mark.django_db
class TestNetworkEvent:
    def test_network_event(self):
        SystemRunningFactory.create_batch(10)
        SystemRunningTask.run(timezone.now())
        assert NetworkEvent.get_queryset(
            content__contains='网口连接异常').exists()


@pytest.mark.django_db
class TestSecurityEvent:
    def test_security_event(self):
        SecurityEventFactory.create_batch(1000, status_resolved=0)
        MainViewTask.run(timezone.now())

        assert SecurityEventLog.get_queryset(content__contains='未处理的安全事件达到')

    def test_alert_event(self):
        DeviceAllAlertFactory.create_batch(1000, status_resolved=0,
                                           level=DeviceAllAlert.LEVEL_HIGH)
        MainViewTask.run(timezone.now())

        assert AlertEvent.get_queryset(content__contains='未处理的安全威胁达到')
        assert HighAlertEvent.get_queryset(content__contains='未处理的高级安全威胁达到')


@pytest.mark.django_db
class TestAssetsEvent:
    def test_assets_event(self):
        device = DeviceFactory.create_normal()
        SNMPSettingFactory.create(device=device)
        client = SNMPClient(device)
        client._result = {
            'cpu_in_use': 100,
            'memory_in_use': 100,
            'process_count': 100,
        }
        client.check_device_healthy()

        assert AssetsCPUEvent.get_queryset(
            content=f'资产CPU使用率达到阈值{AssetsCPUEvent.threshold}%').exists()
        assert AssetsMemoryEvent.get_queryset(
            content=f'资产内存使用率达到阈值{AssetsMemoryEvent.threshold}%').exists()
        assert ProcessEvent.get_queryset(
            content='进程数量异常').exists()

    def test_disk_event(self):
        """
        测试分区超容量告警
        """
        device = DeviceFactory.create_normal()
        SNMPSettingFactory.create(device=device)
        client = SNMPClient(device)
        client._result = {
            'partition_usage':  [
                {'name': 'C:', 'total': 100, 'used': 81, 'percent': 81},
                {'name': 'D:', 'total': 100, 'used': 71, 'percent': 71},
                {'name': 'F:', 'total': 100, 'used': 91, 'percent': 91},
            ]
        }
        client.check_device_healthy()
        assert AssetsDiskEvent.get_queryset(
            content=f'资产分区C:使用率达到阈值{AssetsDiskEvent.threshold}%'
        ).exists()
        assert AssetsDiskEvent.get_queryset(
            content=f'资产分区F:使用率达到阈值{AssetsDiskEvent.threshold}%'
        ).exists()


@pytest.mark.django_db
class TestLogAbnormalEvent:
    def test_log_abnormal(self):
        current = timezone.now()
        last = current - timedelta(days=1)
        LogStatisticDayFactory.create(update_time=last)

        event = LogAbnormalEvent(200, last)
        event.generate()

        assert LogAbnormalEvent.get_queryset(content='今日日志数量异常').exists()