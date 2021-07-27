import pytest
from pytest import fixture

from base_app.factory_data import DeviceFactory, TemplateFactory
from base_app.models import Device, StrategyTemplate
from firewall.factory_data import BaseFirewallStrategyFactory, FirewallWhiteListStrategyFactory, \
    FirewallLearnedWhiteListStrategyFactory, IndustryProtocolModbusStrategyFactory, IndustryProtocolS7StrategyFactory, \
    FirewallIPMACBondStrategyFactory, FirewallSecEventFactory, FirewallSysEventFactory
from utils.base_testcase import BaseTest


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():

        firewall_devices = DeviceFactory.create_batch(BaseTest.list_size, type=Device.FIRE_WALL,
                                                      status=Device.NOT_REGISTERED,
                                                      strategy_apply_status=Device.STRATEGY_APPLY_STATUS_APPLIED)
        for firewall in firewall_devices:
            BaseFirewallStrategyFactory.create_batch(BaseTest.list_size, device=firewall)
            FirewallWhiteListStrategyFactory.create_batch(BaseTest.list_size, device=firewall)
            FirewallLearnedWhiteListStrategyFactory.create_batch(BaseTest.list_size, device=firewall)
            IndustryProtocolModbusStrategyFactory.create_batch(BaseTest.list_size, device=firewall)
            IndustryProtocolS7StrategyFactory.create_batch(BaseTest.list_size, device=firewall)
            FirewallIPMACBondStrategyFactory.create_batch(BaseTest.list_size, device=firewall)
            FirewallSecEventFactory.create_batch(BaseTest.list_size, device=firewall)
            FirewallSysEventFactory.create_batch(BaseTest.list_size, device=firewall)

        firewall_template = TemplateFactory.create_batch(BaseTest.list_size, type=Device.FIRE_WALL)
        for template in firewall_template:
            BaseFirewallStrategyFactory.create_batch(BaseTest.list_size, template=template)
            FirewallWhiteListStrategyFactory.create_batch(BaseTest.list_size, template=template)
            FirewallLearnedWhiteListStrategyFactory.create_batch(BaseTest.list_size, template=template)
            IndustryProtocolModbusStrategyFactory.create_batch(BaseTest.list_size, template=template)
            IndustryProtocolS7StrategyFactory.create_batch(BaseTest.list_size, template=template)
            FirewallIPMACBondStrategyFactory.create_batch(BaseTest.list_size, template=template)


@fixture(scope='class', params=['template', 'device'])
def dev_or_temp(request):
    return request.param


@fixture(scope='class')
def parent_lookup_map():
    return {
        'device': Device.objects.filter(type=Device.FIRE_WALL).latest('id').id,
        'template': StrategyTemplate.objects.filter(type=Device.FIRE_WALL).latest('id').id
    }


@fixture(scope='class')
def parent_lookup_kwargs(dev_or_temp, parent_lookup_map):
    return {'parent_lookup_{}'.format(dev_or_temp): parent_lookup_map.get(dev_or_temp)}


@fixture(scope='class')
def temp_or_device_kwargs(dev_or_temp, parent_lookup_map):
    return {'{}_id'.format(dev_or_temp): parent_lookup_map.get(dev_or_temp)}
