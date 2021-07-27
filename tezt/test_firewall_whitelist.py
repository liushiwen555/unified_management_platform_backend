# import random
# import sys
#
# import faker
# import pytest
# from _pytest.fixtures import fixture
# from django.urls import reverse
# from rest_framework import status
# from rest_framework.permissions import AllowAny
#
# from base_app.models import Device
# from firewall.factory_data import FirewallWhiteListStrategyFactory
# from firewall.models import FirewallWhiteListStrategy, LOGGING_CHOICES, STATUS_CHOICES
# from utils.base_testcase import BaseTest
# from utils.core.permissions import IsSecurityEngineer
#
# fake = faker.Faker('zh_CN')
#
#
# @pytest.mark.django_db
# class TestDeviceWhitelistView(BaseTest):
#
#     url_permission_map = {
#         'white-lists-list': {
#             'get': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#             'post': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#         },
#         'white-lists-detail': {
#             'get': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#             'put': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#             'patch': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#             'delete': {'permission': AllowAny, 'user_identity': ['engineer', 'auditor', 'admin', 'anonymous']},
#         },
#         'white-lists-batch-activation-list': {
#             'put': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#     }
#
#     @fixture(scope='class')
#     def post_data_map(self, temp_or_device_kwargs):
#         return {
#             201: {
#                 'rule_id': [random.randint(1, 1024)],
#                 'rule_name': [fake.pystr(min_chars=1, max_chars=64)],
#                 'src_ip': [fake.ipv4()],
#                 'dst_ip': [fake.ipv4()],
#                 'src_port': [None, random.randint(1, 65535)],
#                 'dst_port': [None, random.randint(1, 65535)],
#                 'protocol': ['', None, 'TCP'],
#                 'logging': [random.choice([item[0] for item in LOGGING_CHOICES])],
#                 'status': [random.choice([item[0] for item in STATUS_CHOICES])],
#             },
#             400: {
#                 'rule_id': ['', None],
#                 'rule_name': ['', None, fake.pystr(min_chars=65, max_chars=65)],
#                 'src_ip': ['', None, 'an invalid ip'],
#                 'dst_ip': ['', None, 'an invalid ip'],
#                 'src_port': [0, 65536],
#                 'dst_port': [0, 65536],
#                 'protocol': [fake.pystr(min_chars=33, max_chars=33)],
#                 'logging': [None, 1000],
#                 'status': [None, 1000],
#             },
#             499: {
#                 'rule_id': [random.choice(
#                     FirewallWhiteListStrategy.objects.filter(**temp_or_device_kwargs).values_list('rule_id',
#                                                                                                   flat=True))]
#             }
#         }
#
#     @fixture(scope='class')
#     def put_data_map(self, temp_or_device_kwargs, detail_id):
#         return {
#             200: {
#                 'rule_id': [random.randint(1, 1024)],
#                 'rule_name': [fake.pystr(min_chars=1, max_chars=64)],
#                 'src_ip': [fake.ipv4()],
#                 'dst_ip': [fake.ipv4()],
#                 'src_port': [None, random.randint(1, 65535)],
#                 'dst_port': [None, random.randint(1, 65535)],
#                 'protocol': ['', None, 'TCP'],
#                 'logging': [random.choice([item[0] for item in LOGGING_CHOICES])],
#                 'status': [random.choice([item[0] for item in STATUS_CHOICES])],
#             },
#             400: {
#                 'rule_id': ['', None],
#                 'rule_name': ['', None, fake.pystr(min_chars=65, max_chars=65)],
#                 'src_ip': ['', None, 'an invalid ip'],
#                 'dst_ip': ['', None, 'an invalid ip'],
#                 'src_port': [0, 65536],
#                 'dst_port': [0, 65536],
#                 'protocol': [fake.pystr(min_chars=33, max_chars=33)],
#                 'logging': [None, 1000],
#                 'status': [None, 1000],
#             },
#             499: {
#                 'rule_id': [random.choice(
#                     FirewallWhiteListStrategy.objects.filter(**temp_or_device_kwargs).exclude(id=detail_id).values_list(
#                         'rule_id', flat=True))]
#             }
#         }
#
#     @property
#     def factory(self):
#         return FirewallWhiteListStrategyFactory
#
#     @fixture(scope='class')
#     def list_url(self, parent_lookup_kwargs):
#         return reverse('firewall:white-lists-list', kwargs=parent_lookup_kwargs)
#
#     @fixture(scope='class')
#     def detail_id(self, temp_or_device_kwargs):
#         return FirewallWhiteListStrategy.objects.filter(**temp_or_device_kwargs).latest('id').id
#
#     @fixture(scope='class')
#     def detail_kwargs(self, parent_lookup_kwargs, detail_id):
#         result = parent_lookup_kwargs.copy()
#         result.update({'pk': detail_id})
#         return result
#
#     @fixture(scope='class')
#     def detail_url(self, detail_kwargs):
#         return reverse('firewall:white-lists-detail', kwargs=detail_kwargs)
#
#     @fixture(scope='class')
#     def invalid_detail_url(self, detail_kwargs):
#         invalid_detail_kwargs = detail_kwargs.copy()
#         invalid_detail_kwargs.update({'pk': sys.maxsize})
#         return reverse('firewall:white-lists-detail', kwargs=invalid_detail_kwargs)
#
#     @fixture(scope='class')
#     def batch_activation_url(self, parent_lookup_kwargs):
#         return reverse('firewall:white-lists-batch-activation-list', kwargs=parent_lookup_kwargs)
#
#     def test_signals(self):
#         device = Device.objects.filter(type=Device.FIRE_WALL).latest('id')
#         strategy = FirewallWhiteListStrategy.objects.filter(device=device).latest('id')
#         device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLIED
#         device.save()
#         strategy.save()
#         device_after_signal = Device.objects.get(id=strategy.device_id)
#         assert device_after_signal.strategy_apply_status == Device.STRATEGY_APPLY_STATUS_UN_APPLIED
#
#     def test_permissions(self, list_url, detail_url, batch_activation_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(batch_activation_url, url_permission_map)
#
#     @pytest.mark.parametrize("whitelist_status", [item[0] for item in STATUS_CHOICES])
#     def test_batch_activation(self, whitelist_status, temp_or_device_kwargs, batch_activation_url):
#         self.engineer()
#         active_response = self.client.put(batch_activation_url, {'status': whitelist_status}, 'json')
#         assert status.is_success(active_response.status_code)
#         assert FirewallWhiteListStrategy.objects.filter(**temp_or_device_kwargs,
#                                                         status=whitelist_status).count() == self.list_size
