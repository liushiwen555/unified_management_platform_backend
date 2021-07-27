# import operator
# import random
# import sys
#
# import faker
# import pytest
# from _pytest.fixtures import fixture
# from django.forms import model_to_dict
# from django.urls import reverse
# from rest_framework import status
# from rest_framework.permissions import AllowAny
#
# from base_app.factory_data import DeviceFactory, TemplateFactory
# from base_app.models import Device, StrategyTemplate
# from firewall.factory_data import ConfStrategyFactory, IndustryProtocolDefaultConfStrategyFactory, \
#     IndustryProtocolOPCStrategyFactory
# from firewall.models import FirewallBlackListStrategy, FirewallBlackList, BaseFirewallStrategy, \
#     FirewallWhiteListStrategy, IndustryProtocolModbusStrategy, \
#     IndustryProtocolS7Strategy, FirewallIPMACBondStrategy, ConfStrategy, IndustryProtocolDefaultConfStrategy, \
#     IndustryProtocolOPCStrategy, FirewallIPMACUnknownDeviceActionStrategy, STATUS_CHOICES
# from utils.base_testcase import BaseTest
# from utils.core.permissions import IsSecurityEngineer, IsConfiEngineer
#
# fake = faker.Faker('zh_CN')
#
#
# @pytest.mark.django_db
# class TestFirewallDeviceView(BaseTest):
#
#     url_permission_map = {
#         'device-list': {
#             'get': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#             'post': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#         },
#         'device-detail': {
#             'get': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#             'put': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#             'patch': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#         },
#         'device-batch-operation-list': {
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'device-clear-unregistered-list': {
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'device-register-list': {
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'device-to-temp': {
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'device-apply-strategies': {
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'device-strategy-conf': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'put': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#         'device-industry-protocol-default-conf-strategy': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'put': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#         'device-industry-protocol-opc-strategy': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'put': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#     }
#
#     @property
#     def factory(self):
#         return DeviceFactory
#
#     @fixture(scope='class')
#     def list_url(self):
#         return reverse('firewall:device-list')
#
#     @fixture(scope='class')
#     def detail_id(self):
#         return Device.objects.filter(type=Device.FIRE_WALL).latest('id').id
#
#     @fixture(scope='class')
#     def detail_url(self, detail_id):
#         return reverse('firewall:device-detail', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def invalid_detail_url(self):
#         return reverse('firewall:device-detail', kwargs={'pk': sys.maxsize})
#
#     @fixture(scope='class')
#     def batch_operation_url(self):
#         return reverse('firewall:device-batch-operation-list')
#
#     @fixture(scope='class')
#     def clear_unregistered_url(self):
#         return reverse('firewall:device-clear-unregistered-list')
#
#     @fixture(scope='class')
#     def register_url(self):
#         return reverse('firewall:device-register-list')
#
#     @fixture(scope='class')
#     def to_temp_url(self, detail_id):
#         return reverse('firewall:device-to-temp', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def apply_strategies_url(self, detail_id):
#         return reverse('firewall:device-apply-strategies', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def strategy_conf_url(self, detail_id):
#         return reverse('firewall:device-strategy-conf', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def industry_protocol_default_conf_strategy_url(self, detail_id):
#         return reverse('firewall:device-industry-protocol-default-conf-strategy', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def industry_protocol_opc_strategy_url(self, detail_id):
#         return reverse('firewall:device-industry-protocol-opc-strategy', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def post_data_map(self):
#         return {
#             201: {
#                 'name': [fake.pystr(min_chars=1, max_chars=20)],
#                 'location': [fake.pystr(min_chars=1, max_chars=20)],
#                 'responsible_user': [fake.pystr(min_chars=1, max_chars=32)],
#             },
#             400: {
#                 'name': ['', None, fake.pystr(min_chars=21, max_chars=21)],
#                 'location': ['', None, fake.pystr(min_chars=21, max_chars=21)],
#                 'responsible_user': ['', None, fake.pystr(min_chars=33, max_chars=33)],
#             },
#         }
#
#     @fixture(scope='class')
#     def put_data_map(self):
#         return {
#             200: {
#                 'name': [fake.pystr(min_chars=1, max_chars=20)],
#                 'location': [fake.pystr(min_chars=1, max_chars=20)],
#                 'responsible_user': [fake.pystr(min_chars=10, max_chars=32)],
#                 'template_name': [None, '', fake.pystr(min_chars=1, max_chars=64)],
#             },
#             400: {
#                 'name': ['', None, fake.pystr(min_chars=21, max_chars=21)],
#                 'location': ['', None, fake.pystr(min_chars=21, max_chars=21)],
#                 'responsible_user': ['', None, fake.pystr(min_chars=33, max_chars=33)],
#                 'template_name': [fake.pystr(min_chars=80, max_chars=80)],
#             },
#         }
#
#     @fixture(scope='class')
#     def strategy_conf_put_data_map(self):
#         return {
#             200: {
#                 'run_mode': [random.choice([item[0] for item in ConfStrategy.RUN_MODE_CHOICES])],
#                 'default_filter': [random.choice([item[0] for item in ConfStrategy.DEFAULT_FILTER_CHOICES])],
#                 'DPI': [random.choice([item[0] for item in ConfStrategy.DPI_CHOICES])],
#             },
#             400: {
#                 'run_mode': [None, 1000],
#                 'default_filter': [None, 1000],
#                 'DPI': [None, 1000]
#             }
#         }
#
#     @fixture(scope='class')
#     def industry_protocol_default_conf_strategy_put_data_map(self):
#         return {
#             200: {
#                 'OPC_default_action': [random.choice([item[0] for item in STATUS_CHOICES])],
#                 'modbus_default_action': [random.choice([item[0] for item in STATUS_CHOICES])],
#             },
#             400: {
#                 'OPC_default_action': [None, 1000],
#                 'modbus_default_action': [None, 1000],
#             },
#         }
#
#     @fixture(scope='class')
#     def industry_protocol_opc_strategy_put_data_map(self):
#         return {
#             200: {
#                 'is_read_open': [True, False],
#                 'read_action': [random.choice([item[0] for item in IndustryProtocolOPCStrategy.READ_WRITE_ACTION_CHOICES])],
#                 'is_write_open': [True, False],
#                 'write_action': [random.choice([item[0] for item in IndustryProtocolOPCStrategy.READ_WRITE_ACTION_CHOICES])],
#             },
#             400: {
#                 'is_read_open': [None, ''],
#                 'read_action': [None, '', 1000],
#                 'is_write_open': [None, ''],
#                 'write_action': [None, '', 1000],
#             },
#         }
#
#     def test_signals(self, detail_id):
#         """
#         device creation signal will trigger blacklists
#         and some per device strategy created to each device,
#
#         :return:
#         """
#         assert ConfStrategy.objects.filter(device_id=detail_id).count() == 1
#         assert IndustryProtocolDefaultConfStrategy.objects.filter(device_id=detail_id).count() == 1
#         assert IndustryProtocolOPCStrategy.objects.filter(device_id=detail_id).count() == 1
#         assert FirewallIPMACUnknownDeviceActionStrategy.objects.filter(device_id=detail_id).count() == 1
#         assert FirewallBlackListStrategy.objects.filter(
#             device_id=detail_id).count() == FirewallBlackList.objects.count()
#
#     def test_permissions(self, list_url, detail_url, batch_operation_url, clear_unregistered_url, register_url,
#                          to_temp_url, apply_strategies_url, strategy_conf_url,
#                          industry_protocol_default_conf_strategy_url,
#                          industry_protocol_opc_strategy_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(batch_operation_url, url_permission_map)
#         self.check_permissions(clear_unregistered_url, url_permission_map)
#         self.check_permissions(register_url, url_permission_map)
#         self.check_permissions(to_temp_url, url_permission_map)
#         self.check_permissions(apply_strategies_url, url_permission_map)
#         self.check_permissions(strategy_conf_url, url_permission_map)
#         self.check_permissions(industry_protocol_default_conf_strategy_url, url_permission_map)
#         self.check_permissions(industry_protocol_opc_strategy_url, url_permission_map)
#
#     def test_get_list(self, list_url, user='engineer', count=BaseTest.list_size):
#         getattr(self, user)()
#         self.engineer()
#         response = self.client.get(list_url)
#         assert response.status_code == status.HTTP_200_OK
#         assert len(response.data) == self.list_size
#         response = self.client.get(list_url, {'page': 1, 'page_size': self.page_size})
#         assert response.status_code == status.HTTP_200_OK
#         assert response.data['count'] == self.list_size
#         assert response.data['page_count'] == self.list_size / self.page_size
#
#     def test_delete(self, **kwargs):
#         pass
#
#     def test_clear_unregistered(self, clear_unregistered_url):
#         self.engineer()
#         self.client.post(clear_unregistered_url)
#         assert Device.objects.filter(type=Device.FIRE_WALL, status=Device.NOT_REGISTERED).count() == 0
#
#     @pytest.mark.parametrize("name", ['', None, fake.pystr(min_chars=33, max_chars=33)])
#     def test_invalid_to_temp(self, name, to_temp_url):
#         self.engineer()
#         response = self.client.post(to_temp_url, {'name': name}, 'json')
#         assert response.status_code == status.HTTP_400_BAD_REQUEST
#
#     def test_valid_to_temp(self, to_temp_url, detail_id):
#         self.engineer()
#         template_name = fake.pystr(min_chars=1, max_chars=32)
#         response = self.client.post(to_temp_url, {'name': template_name}, 'json')
#         template = StrategyTemplate.objects.get(name=template_name)
#         assert BaseFirewallStrategy.objects.filter(
#             device_id=detail_id).count() == BaseFirewallStrategy.objects.filter(template=template).count()
#         assert FirewallWhiteListStrategy.objects.filter(
#             device_id=detail_id).count() == FirewallWhiteListStrategy.objects.filter(template=template).count()
#         assert IndustryProtocolModbusStrategy.objects.filter(
#             device_id=detail_id).count() == IndustryProtocolModbusStrategy.objects.filter(template=template).count()
#         assert IndustryProtocolS7Strategy.objects.filter(
#             device_id=detail_id).count() == IndustryProtocolS7Strategy.objects.filter(template=template).count()
#         assert FirewallIPMACBondStrategy.objects.filter(
#             device_id=detail_id).count() == FirewallIPMACBondStrategy.objects.filter(template=template).count()
#         assert FirewallBlackListStrategy.objects.filter(
#             device_id=detail_id).count() == FirewallBlackListStrategy.objects.filter(template=template).count()
#         assert operator.eq(
#             model_to_dict(ConfStrategy.objects.get(device_id=detail_id), exclude=['id', 'device', 'template']),
#             model_to_dict(ConfStrategy.objects.get(template=template), exclude=['id', 'device', 'template']))
#         assert operator.eq(
#             model_to_dict(IndustryProtocolDefaultConfStrategy.objects.get(device_id=detail_id),
#                           exclude=['id', 'device', 'template']),
#             model_to_dict(IndustryProtocolDefaultConfStrategy.objects.get(template=template),
#                           exclude=['id', 'device', 'template']))
#         assert operator.eq(
#             model_to_dict(IndustryProtocolOPCStrategy.objects.get(device_id=detail_id),
#                           exclude=['id', 'device', 'template']),
#             model_to_dict(IndustryProtocolOPCStrategy.objects.get(template=template),
#                           exclude=['id', 'device', 'template']))
#         assert operator.eq(
#             model_to_dict(FirewallIPMACUnknownDeviceActionStrategy.objects.get(device_id=detail_id),
#                           exclude=['id', 'device', 'template']),
#             model_to_dict(FirewallIPMACUnknownDeviceActionStrategy.objects.get(template=template),
#                           exclude=['id', 'device', 'template']))
#
#         assert status.is_success(response.status_code)
#
#     def test_strategy_conf(self, strategy_conf_url, strategy_conf_put_data_map):
#         self.tezt_data('put', strategy_conf_url, self.engineer_name, ConfStrategyFactory, strategy_conf_put_data_map)
#         self.engineer()
#         response = self.client.get(strategy_conf_url)
#         assert status.is_success(response.status_code)
#
#     def test_industry_protocol_default_conf_strategy(self,
#                                                      industry_protocol_default_conf_strategy_url,
#                                                      industry_protocol_default_conf_strategy_put_data_map):
#         self.tezt_data('put',
#                        industry_protocol_default_conf_strategy_url,
#                        self.engineer_name,
#                        IndustryProtocolDefaultConfStrategyFactory,
#                        industry_protocol_default_conf_strategy_put_data_map)
#         self.engineer()
#         response = self.client.get(industry_protocol_default_conf_strategy_url)
#         assert status.is_success(response.status_code)
#
#     def test_industry_protocol_opc_strategy(self,
#                                             industry_protocol_opc_strategy_url,
#                                             industry_protocol_opc_strategy_put_data_map):
#         self.tezt_data('put',
#                        industry_protocol_opc_strategy_url,
#                        self.engineer_name,
#                        IndustryProtocolOPCStrategyFactory,
#                        industry_protocol_opc_strategy_put_data_map)
#         self.engineer()
#         response = self.client.get(industry_protocol_opc_strategy_url)
#         assert status.is_success(response.status_code)
#
#
# @pytest.mark.django_db
# class TestFirewallTemplateView(BaseTest):
#
#     url_permission_map = {
#         'template-list': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'template-detail': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'put': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#             'patch': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#             'delete': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'template-to-new-temp': {
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'template-deploy-to-device': {
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'template-strategy-conf': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'put': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#         'template-industry-protocol-default-conf-strategy': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'put': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#         'template-industry-protocol-opc-strategy': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'put': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#     }
#
#     @property
#     def factory(self):
#         return TemplateFactory
#
#     @fixture(scope='class')
#     def list_url(self):
#         return reverse('firewall:template-list')
#
#     @fixture(scope='class')
#     def detail_id(self):
#         return StrategyTemplate.objects.filter(type=Device.FIRE_WALL).latest('id').id
#
#     @fixture(scope='class')
#     def detail_url(self, detail_id):
#         return reverse('firewall:template-detail', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def invalid_detail_url(self):
#         return reverse('firewall:template-detail', kwargs={'pk': sys.maxsize})
#
#     @fixture(scope='class')
#     def to_new_temp_url(self, detail_id):
#         return reverse('firewall:template-to-new-temp', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def deploy_to_device_url(self, detail_id):
#         return reverse('firewall:template-deploy-to-device', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def strategy_conf_url(self, detail_id):
#         return reverse('firewall:template-strategy-conf', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def industry_protocol_default_conf_strategy_url(self, detail_id):
#         return reverse('firewall:template-industry-protocol-default-conf-strategy', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def industry_protocol_opc_strategy_url(self, detail_id):
#         return reverse('firewall:template-industry-protocol-opc-strategy', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def post_data_map(self):
#         return {
#             201: {
#                 'name': [fake.pystr(min_chars=1, max_chars=32)]
#             },
#             400: {
#                 'name': ['', None, fake.pystr(min_chars=33, max_chars=33)]
#             }
#         }
#
#     @fixture(scope='class')
#     def put_data_map(self):
#         return {
#             200: {
#                 'name': [fake.pystr(min_chars=1, max_chars=32)]
#             },
#             400: {
#                 'name': ['', None, fake.pystr(min_chars=33, max_chars=33)]
#             }
#         }
#
#     def test_signals(self, detail_id):
#         """
#         template creation signal will trigger blacklists
#         and some per template strategy created to each template,
#
#         :return:
#         """
#         assert ConfStrategy.objects.filter(template_id=detail_id).count() == 1
#         assert IndustryProtocolDefaultConfStrategy.objects.filter(template_id=detail_id).count() == 1
#         assert IndustryProtocolOPCStrategy.objects.filter(template_id=detail_id).count() == 1
#         assert FirewallIPMACUnknownDeviceActionStrategy.objects.filter(template_id=detail_id).count() == 1
#         assert FirewallBlackListStrategy.objects.filter(
#             template_id=detail_id).count() == FirewallBlackList.objects.count()
#
#     def test_permissions(self, list_url,
#                          detail_url,
#                          to_new_temp_url,
#                          deploy_to_device_url,
#                          strategy_conf_url,
#                          industry_protocol_default_conf_strategy_url,
#                          industry_protocol_opc_strategy_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(to_new_temp_url, url_permission_map)
#         self.check_permissions(deploy_to_device_url, url_permission_map)
#         self.check_permissions(strategy_conf_url, url_permission_map)
#         self.check_permissions(industry_protocol_default_conf_strategy_url, url_permission_map)
#         self.check_permissions(industry_protocol_opc_strategy_url, url_permission_map)
#
#     def test_get_list(self, list_url, user='engineer', count=BaseTest.list_size):
#         getattr(self, user)()
#         self.engineer()
#         response = self.client.get(list_url)
#         assert response.status_code == status.HTTP_200_OK
#         assert len(response.data) == self.list_size
#
#     @pytest.mark.parametrize("name", ['', None, fake.pystr(min_chars=33, max_chars=33)])
#     def test_invalid_to_new_temp(self, name, to_new_temp_url):
#         self.engineer()
#         response = self.client.post(to_new_temp_url, {'name': name}, 'json')
#         assert response.status_code == status.HTTP_400_BAD_REQUEST
#
#     def test_valid_to_new_temp(self, to_new_temp_url, detail_id):
#         self.engineer()
#         template_name = fake.pystr(min_chars=1, max_chars=32)
#         response = self.client.post(to_new_temp_url, {'name': template_name}, 'json')
#         template = StrategyTemplate.objects.get(name=template_name)
#         assert BaseFirewallStrategy.objects.filter(
#             template_id=detail_id).count() == BaseFirewallStrategy.objects.filter(template=template).count()
#         assert FirewallWhiteListStrategy.objects.filter(
#             template_id=detail_id).count() == FirewallWhiteListStrategy.objects.filter(template=template).count()
#         assert IndustryProtocolModbusStrategy.objects.filter(
#             template_id=detail_id).count() == IndustryProtocolModbusStrategy.objects.filter(template=template).count()
#         assert IndustryProtocolS7Strategy.objects.filter(
#             template_id=detail_id).count() == IndustryProtocolS7Strategy.objects.filter(template=template).count()
#         assert FirewallIPMACBondStrategy.objects.filter(
#             template_id=detail_id).count() == FirewallIPMACBondStrategy.objects.filter(template=template).count()
#         assert FirewallBlackListStrategy.objects.filter(
#             template_id=detail_id).count() == FirewallBlackListStrategy.objects.filter(template=template).count()
#         assert operator.eq(
#             model_to_dict(ConfStrategy.objects.get(template_id=detail_id), exclude=['id', 'device', 'template']),
#             model_to_dict(ConfStrategy.objects.get(template=template), exclude=['id', 'device', 'template']))
#         assert operator.eq(
#             model_to_dict(IndustryProtocolDefaultConfStrategy.objects.get(template_id=detail_id),
#                           exclude=['id', 'device', 'template']),
#             model_to_dict(IndustryProtocolDefaultConfStrategy.objects.get(template=template),
#                           exclude=['id', 'device', 'template']))
#         assert operator.eq(
#             model_to_dict(IndustryProtocolOPCStrategy.objects.get(template_id=detail_id),
#                           exclude=['id', 'device', 'template']),
#             model_to_dict(IndustryProtocolOPCStrategy.objects.get(template=template),
#                           exclude=['id', 'device', 'template']))
#         assert operator.eq(
#             model_to_dict(FirewallIPMACUnknownDeviceActionStrategy.objects.get(template_id=detail_id),
#                           exclude=['id', 'device', 'template']),
#             model_to_dict(FirewallIPMACUnknownDeviceActionStrategy.objects.get(template=template),
#                           exclude=['id', 'device', 'template']))
#
#         assert status.is_success(response.status_code)
#
#     @pytest.mark.parametrize('dev_ids', [[], None])
#     def test_invalid_deploy_to_device(self, deploy_to_device_url, dev_ids):
#         self.engineer()
#         data = {'dev_ids': dev_ids}
#         response = self.client.post(deploy_to_device_url, data, 'json')
#         assert response.status_code == status.HTTP_400_BAD_REQUEST
#
#     def test_valid_deploy_to_device(self, deploy_to_device_url, detail_id):
#         self.engineer()
#         devices = Device.objects.filter(type=self.get_device_type())
#         deploy_devices = random.sample(list(devices), int(devices.count() / 2))
#         dev_ids = [device.id for device in deploy_devices]
#         data = {'dev_ids': dev_ids}
#         response = self.client.post(deploy_to_device_url, data, 'json')
#         assert status.is_success(response.status_code)
#         for device in deploy_devices:
#             assert BaseFirewallStrategy.objects.filter(
#                 template_id=detail_id).count() == BaseFirewallStrategy.objects.filter(device=device).count()
#             assert FirewallWhiteListStrategy.objects.filter(
#                 template_id=detail_id).count() == FirewallWhiteListStrategy.objects.filter(device=device).count()
#             assert IndustryProtocolModbusStrategy.objects.filter(
#                 template_id=detail_id).count() == IndustryProtocolModbusStrategy.objects.filter(
#                 device=device).count()
#             assert IndustryProtocolS7Strategy.objects.filter(
#                 template_id=detail_id).count() == IndustryProtocolS7Strategy.objects.filter(device=device).count()
#             assert FirewallIPMACBondStrategy.objects.filter(
#                 template_id=detail_id).count() == FirewallIPMACBondStrategy.objects.filter(device=device).count()
#             assert FirewallBlackListStrategy.objects.filter(
#                 template_id=detail_id).count() == FirewallBlackListStrategy.objects.filter(device=device).count()
#             assert operator.eq(
#                 model_to_dict(ConfStrategy.objects.get(template_id=detail_id), exclude=['id', 'device', 'template']),
#                 model_to_dict(ConfStrategy.objects.get(device=device), exclude=['id', 'device', 'template']))
#             assert operator.eq(
#                 model_to_dict(IndustryProtocolDefaultConfStrategy.objects.get(template_id=detail_id),
#                               exclude=['id', 'device', 'template']),
#                 model_to_dict(IndustryProtocolDefaultConfStrategy.objects.get(device=device),
#                               exclude=['id', 'device', 'template']))
#             assert operator.eq(
#                 model_to_dict(IndustryProtocolOPCStrategy.objects.get(template_id=detail_id),
#                               exclude=['id', 'device', 'template']),
#                 model_to_dict(IndustryProtocolOPCStrategy.objects.get(device=device),
#                               exclude=['id', 'device', 'template']))
#             assert operator.eq(
#                 model_to_dict(FirewallIPMACUnknownDeviceActionStrategy.objects.get(template_id=detail_id),
#                               exclude=['id', 'device', 'template']),
#                 model_to_dict(FirewallIPMACUnknownDeviceActionStrategy.objects.get(device=device),
#                               exclude=['id', 'device', 'template']))
#
#     def get_device_type(self):
#         return Device.FIRE_WALL
#
