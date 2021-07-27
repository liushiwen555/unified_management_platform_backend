import pytest
from pytest import fixture

from auditor.factory_data import AuditWhiteListStrategyFactory, \
    AuditIPMACBondStrategyFactory, AuditSecAlertFactory, AuditSysAlertFactory, AuditLogFactory
from base_app.factory_data import DeviceFactory, TemplateFactory
from base_app.models import Device, StrategyTemplate
from log.factory_data import UnifiedForumLogFactory
from utils.base_testcase import BaseTest
from utils.unified_redis import rs
from auditor.bolean_auditor.synchronize import DeviceCache


# @pytest.fixture(scope='session')
# def django_db_setup(django_db_setup, django_db_blocker):
#     with django_db_blocker.unblock():
#
#         UnifiedForumLogFactory.create_batch(BaseTest.list_size)
#         audit_devices = DeviceFactory.create_batch(BaseTest.list_size, type=Device.AUDITOR,
#                                                    status=Device.NOT_REGISTERED,
#                                                    strategy_apply_status=Device.STRATEGY_APPLY_STATUS_APPLIED)
#         for audit in audit_devices:
#             AuditWhiteListStrategyFactory.create_batch(BaseTest.list_size, device=audit)
#             AuditIPMACBondStrategyFactory.create_batch(BaseTest.list_size, device=audit)
#             AuditSecAlertFactory.create_batch(BaseTest.list_size, device=audit)
#             AuditSysAlertFactory.create_batch(BaseTest.list_size, device=audit)
#             AuditLogFactory.create_batch(BaseTest.list_size, device=audit)
#
#         audit_template = TemplateFactory.create_batch(BaseTest.list_size, type=Device.AUDITOR)
#         for template in audit_template:
#             AuditWhiteListStrategyFactory.create_batch(BaseTest.list_size, template=template)
#             AuditIPMACBondStrategyFactory.create_batch(BaseTest.list_size, template=template)


@fixture(scope='class', params=['template', 'device'])
def dev_or_temp(request):
    return request.param


@fixture(scope='class')
def parent_lookup_map():
    return {
        'device': Device.objects.filter(type=Device.AUDITOR).latest('id').id,
        'template': StrategyTemplate.objects.filter(type=Device.AUDITOR).latest('id').id
    }


@fixture(scope='class')
def parent_lookup_kwargs(dev_or_temp, parent_lookup_map):
    return {'parent_lookup_{}'.format(dev_or_temp): parent_lookup_map.get(dev_or_temp)}


@fixture(scope='class')
def temp_or_device_kwargs(dev_or_temp, parent_lookup_map):
    return {'{}_id'.format(dev_or_temp): parent_lookup_map.get(dev_or_temp)}


def pytest_runtestloop(session):
    print('清理资产的缓存')
    keys = rs.keys(DeviceCache.key_pattern + '*')
    for key in keys:
        rs.delete(keys)

# @fixture(scope='class', params=[1,2])
# def aaa(request):
#     return request.param
#
#
# @fixture(scope='class')
# def bbb(aaa):
#     return aaa
