import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from log.factory_data import DeviceAllAlertFactory
from log.models import DeviceAllAlert
from setting.models import Setting
from statistic.factory_data import SystemRunningFactory
from user.models import User, Group, UserExtension, GROUP_ADMIN
from utils.base_testcase import BaseViewTest, BaseUser


@pytest.mark.django_db
class TestSystemInfoView(BaseViewTest):
    def test_system_info(self, config_client: APIClient):
        response = config_client.get(reverse('system-info')).json()

        assert response['cpu_cores'] > 0
        assert response['disk'] > 0
        assert response['memory'] > 0


@pytest.mark.django_db
class TestSystemStatus(BaseViewTest):
    def test_system_status(self, config_client: APIClient):
        d = SystemRunningFactory.create()
        setting, _ = Setting.objects.get_or_create(id=1)
        setting.cpu_alert_percent = 60
        setting.memory_alert_percent = 70
        setting.disk_alert_percent = 80
        setting.save()
        response = config_client.get(reverse('system-running')).json()

        assert response['cpu'] == d.cpu
        assert response['disk'] == d.disk
        assert response['cpu_percent'] == setting.cpu_alert_percent
        assert response['disk_percent'] == setting.disk_alert_percent
        assert response['memory_percent'] == setting.memory_alert_percent


@pytest.mark.django_db
class TestUnResolvedAlertView(BaseViewTest):
    def test_un_resolved_alert(self, config_client: APIClient):
        DeviceAllAlertFactory.create_batch(100)
        response = config_client.get(reverse('unresolved-alert')).json()

        assert response['data'] == DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count()


@pytest.mark.django_db
class TestUserInfoView(BaseViewTest):
    @pytest.fixture(scope='class')
    def users(self):
        groups = Group.objects.all()
        cnt = 0
        for g in groups:
            User.objects.create_user(username='userinfo' + str(cnt),
                                     password=BaseUser.right_password, group=g)
            UserExtension.objects.create(name='userinfo' + str(cnt),
                                         banned=True,
                                         last_failure=timezone.now())
            cnt += 1
        User.objects.filter(group=groups[0]).update(un_modify_passwd=True)

    def test_user_info_view(self, config_client: APIClient, users):
        response = config_client.get(reverse('user-info')).json()

        assert response['admin'] == User.objects.filter(
            group=Group.objects.get(name=GROUP_ADMIN)).count()
        assert response['total'] == User.objects.count()
        assert response['un_modify_passwd'] == User.objects.filter(
            un_modify_passwd=True).count()
        assert response['banned'] == UserExtension.objects.filter(
            banned=True).count()
