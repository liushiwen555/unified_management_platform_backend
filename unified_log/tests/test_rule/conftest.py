import pytest

from unified_log.factory_data import LogProcessRuleFactory, \
    LogProcessTemplateFactory
from unified_log.models import *
from base_app.factory_data import DeviceFactory
from unified_log.log_regex import ASUS_ROUTER, WINDOWS


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    asus_rule_template(django_db_blocker)
    windows_rule_template(django_db_blocker)


def asus_rule_template(django_db_blocker):
    print('生成华硕路由器日志规则')
    with django_db_blocker.unblock():
        asus_kern = LogProcessRuleFactory.create(
            name='kern', pattern=ASUS_ROUTER['kern'], log_type=LOG_ROUTER_ASUS,
        )
        asus_daemon = LogProcessRuleFactory.create(
            name='daemon', pattern=ASUS_ROUTER['daemon'], log_type=LOG_ROUTER_ASUS,
        )
        asus_authpriv = LogProcessRuleFactory.create(
            name='authpriv', pattern=ASUS_ROUTER['authpriv'], log_type=LOG_ROUTER_ASUS,
        )
        asus_user = LogProcessRuleFactory.create(
            name='user', pattern=ASUS_ROUTER['user'], log_type=LOG_ROUTER_ASUS
        )
        local0 = LogProcessRuleFactory.create(
            name='asuslocal', pattern=ASUS_ROUTER['local0'], log_type=LOG_ROUTER_ASUS
        )
        asus_template = LogProcessTemplateFactory.create(
            kern=asus_kern, daemon=asus_daemon, authpriv=asus_authpriv,
            user=asus_user, local0=local0,
        )
        device = DeviceFactory.create_normal(ip='192.168.0.130')
        device.log_template = asus_template
        device.log_status = True
        device.save()


def windows_rule_template(django_db_blocker):
    print('生成Windows日志规则')
    with django_db_blocker.unblock():
        local0 = LogProcessRuleFactory.create(
            name='windows', pattern=WINDOWS['local0'], log_type=LOG_WINDOWS,
        )
        template = LogProcessTemplateFactory.create(
            local0=local0
        )
        device = DeviceFactory.create_normal(ip='10.0.11.25', log_status=True,
                                             log_template=template)
