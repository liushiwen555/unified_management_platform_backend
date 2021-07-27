# import sys
#
# import faker
# import pytest
# from django.urls import reverse
# from pytest import fixture
# from rest_framework import status
#
# from auditor.factory_data import AuditBlackListStrategyFactory
# from auditor.models import AuditorBlackList, AuditBlackListStrategy
# from base_app.models import Device
# from utils.base_testcase import BaseTest
# from utils.core.permissions import IsSecurityEngineer, IsConfiEngineer
#
# fake = faker.Faker('zh_CN')
#
#
# @pytest.mark.django_db
# class TestDeviceBlackListStrategyView(BaseTest):
#
#     url_permission_map = {
#         'black-lists-list': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#         'black-lists-detail': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#         'black-lists-activation': {
#             'put': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#         'black-lists-batch-activation-list': {
#             'put': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#     }
#
#     @property
#     def factory(self):
#         return AuditBlackListStrategyFactory
#
#     @fixture(scope='class')
#     def list_url(self, parent_lookup_kwargs):
#         return reverse('auditor:black-lists-list', kwargs=parent_lookup_kwargs)
#
#     @fixture(scope='class')
#     def detail_id(self, temp_or_device_kwargs):
#         return AuditBlackListStrategy.objects.filter(**temp_or_device_kwargs).latest('id').id
#
#     @fixture(scope='class')
#     def detail_url(self, parent_lookup_kwargs, detail_id):
#         detail_url_kwargs = parent_lookup_kwargs.copy()
#         detail_url_kwargs.update({'pk': detail_id})
#         return reverse('auditor:black-lists-detail', kwargs=detail_url_kwargs)
#
#     @fixture(scope='class')
#     def invalid_detail_url(self, parent_lookup_kwargs):
#         invalid_detail_url_kwargs = parent_lookup_kwargs.copy()
#         invalid_detail_url_kwargs.update({'pk': sys.maxsize})
#         return reverse('auditor:black-lists-detail', kwargs=invalid_detail_url_kwargs)
#
#     @fixture(scope='class')
#     def activation_url(self, parent_lookup_kwargs, detail_id):
#         kwargs = parent_lookup_kwargs.copy()
#         kwargs.update({'pk': detail_id})
#         return reverse('auditor:black-lists-activation', kwargs=kwargs)
#
#     @fixture(scope='class')
#     def batch_activation_url(self, parent_lookup_kwargs):
#         return reverse('auditor:black-lists-batch-activation-list', kwargs=parent_lookup_kwargs)
#
#     def test_delete(self, **kwargs):
#         pass
#
#     def test_get_list(self, list_url, user='engineer', count=BaseTest.list_size):
#         super(TestDeviceBlackListStrategyView, self).test_get_list(list_url, user, AuditorBlackList.objects.count())
#
#     def test_permissions(self, list_url, detail_url, activation_url, batch_activation_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(activation_url, url_permission_map)
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(batch_activation_url, url_permission_map)
#
#     @pytest.mark.parametrize("is_active", [True, False])
#     def test_activation(self, is_active, detail_id, activation_url):
#         self.engineer()
#         active_response = self.client.put(activation_url, {'is_active': is_active}, 'json')
#         assert status.is_success(active_response.status_code)
#         assert AuditBlackListStrategy.objects.get(id=detail_id).is_active == is_active
#
#     @pytest.mark.parametrize("is_active", [True, False])
#     def test_batch_activation(self, is_active, temp_or_device_kwargs, batch_activation_url):
#         self.engineer()
#         active_response = self.client.put(batch_activation_url, {'is_active': is_active}, 'json')
#         assert status.is_success(active_response.status_code)
#         assert AuditBlackListStrategy.objects.filter(**temp_or_device_kwargs,
#                                                      is_active=is_active).count() == AuditorBlackList.objects.count()
#
#     def test_signals(self):
#         device = Device.objects.filter(type=Device.AUDITOR).latest('id')
#         blacklist = AuditBlackListStrategy.objects.filter(device=device).latest('id')
#         device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLIED
#         device.save()
#         blacklist.save()
#         device_after_signal = Device.objects.get(id=blacklist.device_id)
#         assert device_after_signal.strategy_apply_status == Device.STRATEGY_APPLY_STATUS_UN_APPLIED
