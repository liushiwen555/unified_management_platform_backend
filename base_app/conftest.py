import pytest

from unified_log.factory_data import LogProcessTemplateFactory, \
    LogProcessRuleFactory
from base_app.factory_data import DeviceFactory


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        DeviceFactory.create_batch(5, strategy_apply_status=1)
        LogProcessRuleFactory.create_batch(20)
        LogProcessTemplateFactory.create()
