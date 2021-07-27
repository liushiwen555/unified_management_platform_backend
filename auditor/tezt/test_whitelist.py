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
# from auditor.factory_data import AuditWhiteListStrategyFactory
# from auditor.models import AuditWhiteListStrategy
# from base_app.models import Device
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
#             'get': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#             'post': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#         },
#         'white-lists-detail': {
#             'get': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#             'put': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#             'patch': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#             'delete': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#         },
#         'white-lists-batch-activation-list': {
#             'put': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#     }
#
#     @fixture(scope='class')
#     def post_data_map(self):
#         return {
#             201: {
#                 'name': [None, fake.pystr(min_chars=1, max_chars=20)],
#                 'level': [random.choice([item[0] for item in AuditWhiteListStrategy.LEVEL_CHOICE])],
#                 'src_ip': [fake.ipv4()],
#                 'src_ports': ['', None, '1:2', '100', '200:300,400'],
#                 'dst_ip': [fake.ipv4()],
#                 'dst_ports': ['', None, '1:2', '100', '200:300,400'],
#                 'is_active': [True, False],
#             },
#             400: {
#                 'name': ['', fake.pystr(min_chars=21, max_chars=21)],
#                 'level': [None, random.choice(
#                     [i for i in range(0, 10) if i not in [item[0] for item in AuditWhiteListStrategy.LEVEL_CHOICE]])],
#                 'src_ip': ['', None, 'not a valid ip'],
#                 'src_ports': ['not a valid ports format'],
#                 'dst_ip': ['', None, 'not a valid ip'],
#                 'dst_ports': ['not a valid ports format'],
#                 'is_active': ['', None],
#             }
#         }
#
#     @fixture(scope='class')
#     def put_data_map(self):
#         return {
#             200: {
#                 'name': [None, fake.pystr(min_chars=1, max_chars=20)],
#                 'level': [random.choice([item[0] for item in AuditWhiteListStrategy.LEVEL_CHOICE])],
#                 'src_ip': [fake.ipv4()],
#                 'src_ports': ['', None, '1:2', '100', '200:300,400'],
#                 'dst_ip': [fake.ipv4()],
#                 'dst_ports': ['', None, '1:2', '100', '200:300,400'],
#                 'is_active': [True, False],
#             },
#             400: {
#                 'name': ['', fake.pystr(min_chars=21, max_chars=21)],
#                 'level': [None, random.choice(
#                     [i for i in range(0, 10) if i not in [item[0] for item in AuditWhiteListStrategy.LEVEL_CHOICE]])],
#                 'src_ip': ['', None, 'not a valid ip'],
#                 'src_ports': ['not a valid ports format'],
#                 'dst_ip': ['', None, 'not a valid ip'],
#                 'dst_ports': ['not a valid ports format'],
#                 'is_active': ['', None],
#             }
#         }
#
#     @property
#     def factory(self):
#         return AuditWhiteListStrategyFactory
#
#     @fixture(scope='class')
#     def list_url(self, parent_lookup_kwargs):
#         return reverse('auditor:white-lists-list', kwargs=parent_lookup_kwargs)
#
#     @fixture(scope='class')
#     def detail_id(self, temp_or_device_kwargs):
#         return AuditWhiteListStrategy.objects.filter(**temp_or_device_kwargs).latest('id').id
#
#     @fixture(scope='class')
#     def detail_kwargs(self, parent_lookup_kwargs, detail_id):
#         result = parent_lookup_kwargs.copy()
#         result.update({'pk': detail_id})
#         return result
#
#     @fixture(scope='class')
#     def detail_url(self, detail_kwargs):
#         return reverse('auditor:white-lists-detail', kwargs=detail_kwargs)
#
#     @fixture(scope='class')
#     def invalid_detail_url(self, detail_kwargs):
#         invalid_detail_kwargs = detail_kwargs.copy()
#         invalid_detail_kwargs.update({'pk': sys.maxsize})
#         return reverse('auditor:white-lists-detail', kwargs=invalid_detail_kwargs)
#
#     @fixture(scope='class')
#     def batch_activation_url(self, parent_lookup_kwargs):
#         return reverse('auditor:white-lists-batch-activation-list', kwargs=parent_lookup_kwargs)
#
#     def test_signals(self):
#         device = Device.objects.filter(type=Device.AUDITOR).latest('id')
#         aws = AuditWhiteListStrategy.objects.filter(device=device).latest('id')
#         device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLIED
#         device.save()
#         aws.save()
#         device_after_signal = Device.objects.get(id=aws.device_id)
#         assert device_after_signal.strategy_apply_status == Device.STRATEGY_APPLY_STATUS_UN_APPLIED
#
#     def test_permissions(self, list_url, detail_url, batch_activation_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(batch_activation_url, url_permission_map)
#
#     @pytest.mark.parametrize("is_active", [True, False])
#     def test_batch_activation(self, is_active, temp_or_device_kwargs, batch_activation_url):
#         self.engineer()
#         active_response = self.client.put(batch_activation_url, {'is_active': is_active}, 'json')
#         assert status.is_success(active_response.status_code)
#         assert AuditWhiteListStrategy.objects.filter(**temp_or_device_kwargs,
#                                                      is_active=is_active).count() == self.list_size
