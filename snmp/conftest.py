import pytest

from snmp.factory_data import SNMPRuleFactory, SNMPTemplateFactory, SNMPSettingFactory


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        SNMPRuleFactory.create_batch(5)
        SNMPTemplateFactory.create_batch(5)
        SNMPSettingFactory.create_batch(5)
