# import sys
#
# import faker
# import pytest
# from _pytest.fixtures import fixture
# from django.urls import reverse
# from rest_framework import status
#
# from auditor.factory_data import AuditIPMACBondStrategyFactory
# from auditor.models import AuditIPMACBondStrategy
# from base_app.models import Device
# from utils.base_testcase import BaseTest
# from utils.core.permissions import IsSecurityEngineer, IsConfiEngineer
#
# fake = faker.Faker('zh_CN')
#
#
# @pytest.mark.django_db
# class TestIPMACBondStrategyView(BaseTest):
#     url_permission_map = {
#         'ip-mac-bond-list': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'post': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'ip-mac-bond-detail': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#             'put': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#             'patch': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#             'delete': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'ip-mac-bond-batch-bond-list': {
#             'put': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#     }
#
#     @property
#     def factory(self):
#         return AuditIPMACBondStrategyFactory
#
#     @fixture(scope='class')
#     def post_data_map(self):
#         return {
#             201: {
#                 'name': ['', fake.pystr(min_chars=1, max_chars=20)],
#                 'ip': [fake.ipv4()],
#                 'mac': [fake.mac_address()],
#                 'ip_mac_bond': [True, False]
#             },
#             400: {
#                 'name': [None, fake.pystr(min_chars=21, max_chars=21)],
#                 'ip': ['', None, 'not a valid ip'],
#                 'mac': ['', None, 'not a valid mac'],
#                 'ip_mac_bond': ['', None, 'xxx']
#             },
#         }
#
#     @fixture(scope='class')
#     def put_data_map(self):
#         return {
#             200: {
#                 'name': ['', fake.pystr(min_chars=1, max_chars=20)],
#                 'ip': [fake.ipv4()],
#                 'mac': [fake.mac_address()],
#                 'ip_mac_bond': [True, False]
#             },
#             400: {
#                 'name': [None, fake.pystr(min_chars=21, max_chars=21)],
#                 'ip': ['', None, 'not a valid ip'],
#                 'mac': ['', None, 'not a valid mac'],
#                 'ip_mac_bond': ['', 'xxx', None]
#             },
#         }
#
#     @fixture(scope='class')
#     def list_url(self, parent_lookup_kwargs):
#         return reverse('auditor:ip-mac-bond-list', kwargs=parent_lookup_kwargs)
#
#     @fixture(scope='class')
#     def detail_id(self, temp_or_device_kwargs):
#         return AuditIPMACBondStrategy.objects.filter(**temp_or_device_kwargs).latest('id').id
#
#     @fixture(scope='class')
#     def detail_kwargs(self, parent_lookup_kwargs, detail_id):
#         result = parent_lookup_kwargs.copy()
#         result.update({'pk': detail_id})
#         return result
#
#     @fixture(scope='class')
#     def detail_url(self, detail_kwargs):
#         return reverse('auditor:ip-mac-bond-detail', kwargs=detail_kwargs)
#
#     @fixture(scope='class')
#     def invalid_detail_url(self, detail_kwargs):
#         invalid_detail_kwargs = detail_kwargs.copy()
#         invalid_detail_kwargs.update({'pk': sys.maxsize})
#         return reverse('auditor:ip-mac-bond-detail', kwargs=invalid_detail_kwargs)
#
#     @fixture(scope='class')
#     def batch_bond_url(self, parent_lookup_kwargs):
#         return reverse('auditor:ip-mac-bond-batch-bond-list', kwargs=parent_lookup_kwargs)
#
#     def test_permissions(self, list_url, detail_url, batch_bond_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(batch_bond_url, url_permission_map)
#
#     @pytest.mark.parametrize("ip_mac_bond", [True, False])
#     def test_batch_bond(self, ip_mac_bond, temp_or_device_kwargs, batch_bond_url):
#         self.engineer()
#         response = self.client.put(batch_bond_url, {'ip_mac_bond': ip_mac_bond}, 'json')
#         assert status.is_success(response.status_code), response.data
#         assert AuditIPMACBondStrategy.objects.filter(**temp_or_device_kwargs,
#                                                      ip_mac_bond=ip_mac_bond).count() == self.list_size
#
#     def test_signals(self):
#         device = Device.objects.filter(type=Device.AUDITOR).latest('id')
#         aimb = AuditIPMACBondStrategy.objects.filter(device=device).latest('id')
#         device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLIED
#         device.save()
#         aimb.save()
#         device_after_signal = Device.objects.get(id=aimb.device_id)
#         assert device_after_signal.strategy_apply_status == Device.STRATEGY_APPLY_STATUS_UN_APPLIED
