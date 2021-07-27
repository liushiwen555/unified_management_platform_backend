from datetime import timedelta

import pytest
from django.utils import timezone

from log.models import UnifiedForumLog
from user.models import User, Group, UserExtension
from utils.base_testcase import BaseUser
from setting.models import Setting
from log.tasks import check_user_pwd_modified


@pytest.mark.django_db
class TestCheckUserPassword:
    @pytest.fixture(scope='class')
    def user(self) -> User:
        group = Group.objects.first()
        user = User.objects.create_user('test222',
                                        password=BaseUser.right_password,
                                        group=group)
        return user

    @pytest.fixture(scope='class')
    def setting(self) -> Setting:
        setting, _ = Setting.objects.get_or_create(id=1)
        setting.change_psw_duration = 1
        setting.save()
        return setting

    def test_check(self, user: User, setting: Setting):
        user_ext, _ = UserExtension.objects.get_or_create(name=user.username)
        user_ext.last_change_psd = timezone.now() - timedelta(days=2)
        user_ext.save()

        check_user_pwd_modified()

        log = UnifiedForumLog.objects.filter(
            user=user.username, group=user.group.name,
            category=UnifiedForumLog.CATEGORY_SYSTEM,
            type=UnifiedForumLog.TYPE_AUTH_SECURITY
        )
        assert log.exists()

