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
class TestLockedUser(BaseViewTest):
    @pytest.fixture(scope='function')
    def users(self):
        ext, _ = UserExtension.objects.get_or_create(name=BaseUser.admin_name)
        ext.banned = True
        ext.last_failure = timezone.now()
        ext.save()
        ext, _ = UserExtension.objects.get_or_create(name=BaseUser.engineer_name)
        ext.banned = True
        ext.last_failure = timezone.now()
        ext.save()
        UserExtension.objects.create(name='fukumura', banned=True,
                                     last_failure=timezone.now())

    def test_locked_user(self, config_client: APIClient, users):
        response = config_client.get(reverse('abnormal-behavior')).json()
        locked_user = response['locked_user']
        assert len(locked_user) == 3
        assert locked_user[0]['name'] == 'fukumura'
        assert locked_user[1]['name'] == BaseUser.engineer_name
        assert locked_user[2]['name'] == BaseUser.admin_name
