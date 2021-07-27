import pytest

from auditor.factory_data import AuditSysAlertFactory, AuditSecAlertFactory
from base_app.factory_data import DeviceFactory
from base_app.models import Device
from log.factory_data import DeviceAllAlertFactory, SecurityEventFactory, \
    UnifiedForumLogFactory
from unified_log.elastic.elastic_client import client


def pytest_runtestloop(session):
    print('开始测试运营态势任务')
    print('清理elasticsearch')
    client.delete_template('test-*')
    client.delete_index('test-*')
    client.create_template(
        'test-log-statistic',
        {
            'mappings': {
                'properties':
                    {
                        'dev_category': {'type': 'keyword'},
                        'dst_ip': {'type': 'keyword'},
                        'dst_port': {'type': 'integer'},
                        'dev_id': {'type': 'integer'},
                    }
            },
            'index_patterns': 'test-log-statistic-*'
        }
    )


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    print('准备运营态势的测试数据')
    with django_db_blocker.unblock():
        for category in Device.CATEGORY_CHOICE:
            DeviceFactory.create_batch_normal(2, category=category[0])
        DeviceAllAlertFactory.create_batch(10)
        SecurityEventFactory.create_batch(10)
        UnifiedForumLogFactory.create_batch(10)
        AuditSecAlertFactory.create_batch(10)
        AuditSysAlertFactory.create_batch(10)
