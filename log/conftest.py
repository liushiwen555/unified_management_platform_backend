import pytest

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from log.factory_data import UnifiedForumLogFactory
from user.factory_data import UserFactory
from utils.base_testcase import BaseTest


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):

    with django_db_blocker.unblock():
        list_size = BaseTest.list_size
        # 不同 log 生成，用来测试 list_url及 detail_url
        # UnifiedForumLogFactory.create_batch(list_size)

        DeviceFactory.create_batch(BaseTest.list_size,
                                   type=Device.AUDITOR,
                                   status=Device.NOT_REGISTERED,
                                   strategy_apply_status=Device.STRATEGY_APPLY_STATUS_APPLIED)
