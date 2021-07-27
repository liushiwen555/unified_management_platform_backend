import pytest
from faker import Faker

from unified_log.elastic.elastic_client import client
from unified_log.factory_data import LogProcessRuleFactory, \
    LogProcessTemplateFactory
from unified_log.models import *
from base_app.factory_data import DeviceFactory
from unified_log.log_process import device_cache
from unified_log.elastic.elastic_model import template_register
from unified_log.log_regex import regex_dict


fake = Faker()


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        # 默认创建一个auth log解析规则，测试一般使用这个，对规则单独测试的时候，使用完整
        # 的规则列表
        auth = LogProcessRuleFactory.create(
            pattern=regex_dict['auth'], log_type=LOG_AUTH)
        kern = LogProcessRuleFactory.create(
            pattern=regex_dict['kern'], log_type=LOG_KERNEL)
        daemon = LogProcessRuleFactory.create(
            pattern=regex_dict['daemon'], log_type=LOG_DAEMON)
        cron = LogProcessRuleFactory.create(
            pattern=regex_dict['cron'], log_type=LOG_CRON)
        syslog = LogProcessRuleFactory.create(
            pattern=regex_dict['syslog'], log_type=LOG_SYSLOG)
        authpriv = LogProcessRuleFactory.create(
            pattern=regex_dict['authpriv'], log_type=LOG_AUTHPRIV
        )
        mail = LogProcessRuleFactory.create(
            pattern=regex_dict['mail'], log_type=LOG_MAIL
        )
        ftp = LogProcessRuleFactory.create(
            pattern=regex_dict['ftp'], log_type=LOG_FTP
        )
        local0 = LogProcessRuleFactory.create(
            pattern=regex_dict['audit-alarm'], log_type=LOG_AUDIT_ALARM
        )
        local1 = LogProcessRuleFactory.create(
            pattern=regex_dict['nginx'], log_type=LOG_NGINX,
        )
        local7 = LogProcessRuleFactory.create(
            pattern=regex_dict['huawei_switch'], log_type=LOG_SWITCH_HUAWEI
        )
        local2 = LogProcessRuleFactory.create(
            pattern=regex_dict['database_postgres'],
            log_type=LOG_DATABASE_POSTGRESQL,
        )
        template = LogProcessTemplateFactory.create(
            auth=auth, kern=kern, daemon=daemon, cron=cron, syslog=syslog,
            local0=local0, local1=local1, local2=local2, local3=None, local4=None,
            local5=None, local6=None, local7=local7, authpriv=authpriv, mail=mail,
            lpr=None, ftp=ftp
        )
        device = DeviceFactory.create(ip='192.168.0.58')
        device.log_template = template
        device.save()


def pytest_runtestloop(session):
    print('开始测试日志功能')
    print('清理elasticsearch和redis缓存')
    device_cache.clean()
    client.delete_template('test-*')
    client.delete_index('test-*')
    template_register.save_template()
