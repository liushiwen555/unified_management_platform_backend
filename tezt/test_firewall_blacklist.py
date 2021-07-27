# import sys
#
# import faker
# import pytest
# from django.urls import reverse
# from pytest import fixture
# from rest_framework import status
#
# from base_app.models import Device
# from firewall.factory_data import FirewallBlackListStrategyFactory
# from firewall.models import FirewallBlackList, FirewallBlackListStrategy, STATUS_CHOICES
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
#             'put': {'permission': IsSecurityEngineer, 'user_identity': ['engineer']},
#         },
#     }
#
#     @property
#     def factory(self):
#         return FirewallBlackListStrategyFactory
#
#     @fixture(scope='class')
#     def list_url(self, parent_lookup_kwargs):
#         return reverse('firewall:black-lists-list', kwargs=parent_lookup_kwargs)
#
#     @fixture(scope='class')
#     def detail_id(self, temp_or_device_kwargs):
#         return FirewallBlackListStrategy.objects.filter(**temp_or_device_kwargs).latest('id').id
#
#     @fixture(scope='class')
#     def detail_url(self, parent_lookup_kwargs, detail_id):
#         detail_url_kwargs = parent_lookup_kwargs.copy()
#         detail_url_kwargs.update({'pk': detail_id})
#         return reverse('firewall:black-lists-detail', kwargs=detail_url_kwargs)
#
#     @fixture(scope='class')
#     def invalid_detail_url(self, parent_lookup_kwargs):
#         invalid_detail_url_kwargs = parent_lookup_kwargs.copy()
#         invalid_detail_url_kwargs.update({'pk': sys.maxsize})
#         return reverse('firewall:black-lists-detail', kwargs=invalid_detail_url_kwargs)
#
#     @fixture(scope='class')
#     def activation_url(self, parent_lookup_kwargs, detail_id):
#         kwargs = parent_lookup_kwargs.copy()
#         kwargs.update({'pk': detail_id})
#         return reverse('firewall:black-lists-activation', kwargs=kwargs)
#
#     @fixture(scope='class')
#     def batch_activation_url(self, parent_lookup_kwargs):
#         return reverse('firewall:black-lists-batch-activation-list', kwargs=parent_lookup_kwargs)
#
#     @fixture(scope='class')
#     def action_url(self, parent_lookup_kwargs, detail_id):
#         kwargs = parent_lookup_kwargs.copy()
#         kwargs.update({'pk': detail_id})
#         return reverse('firewall:black-lists-action', kwargs=kwargs)
#
#     @fixture(scope='class')
#     def batch_action_url(self, parent_lookup_kwargs):
#         return reverse('firewall:black-lists-batch-action-list', kwargs=parent_lookup_kwargs)
#
#     def test_delete(self, **kwargs):
#         pass
#
#     def test_get_list(self, list_url, user='engineer', count=BaseTest.list_size):
#         super(TestDeviceBlackListStrategyView, self).test_get_list(list_url, user, FirewallBlackList.objects.count())
#
#     def test_permissions(self, list_url, detail_url, activation_url, batch_activation_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(activation_url, url_permission_map)
#         self.check_permissions(batch_activation_url, url_permission_map)
#
#     @pytest.mark.parametrize("blacklist_status", [item[0] for item in STATUS_CHOICES])
#     def test_activation(self, blacklist_status, detail_id, activation_url):
#         self.engineer()
#         active_response = self.client.put(activation_url, {'status': blacklist_status}, 'json')
#         assert status.is_success(active_response.status_code)
#         assert FirewallBlackListStrategy.objects.get(id=detail_id).status == blacklist_status
#
#     @pytest.mark.parametrize("blacklist_status", [item[0] for item in STATUS_CHOICES])
#     def test_batch_activation(self, blacklist_status, temp_or_device_kwargs, batch_activation_url):
#         self.engineer()
#         active_response = self.client.put(batch_activation_url, {'status': blacklist_status}, 'json')
#         assert status.is_success(active_response.status_code)
#         assert FirewallBlackListStrategy.objects.filter(
#             **temp_or_device_kwargs,
#             status=blacklist_status).count() == FirewallBlackList.objects.count()
#
#     @pytest.mark.parametrize("action", [item[0] for item in FirewallBlackListStrategy.EVENT_PROCESS_CHOICES])
#     def test_action(self, action, detail_id, action_url):
#         self.engineer()
#         active_response = self.client.put(action_url, {'action': action}, 'json')
#         assert status.is_success(active_response.status_code)
#         assert FirewallBlackListStrategy.objects.get(id=detail_id).action == action
#
#     @pytest.mark.parametrize("action", [item[0] for item in FirewallBlackListStrategy.EVENT_PROCESS_CHOICES])
#     def test_batch_action(self, action, temp_or_device_kwargs, batch_action_url):
#         self.engineer()
#         response = self.client.put(batch_action_url, {'action': action}, 'json')
#         assert status.is_success(response.status_code), response.data
#         assert FirewallBlackListStrategy.objects.filter(
#             **temp_or_device_kwargs,
#             action=action).count() == FirewallBlackList.objects.count()
#
#     def test_signals(self):
#         device = Device.objects.filter(type=Device.FIRE_WALL).latest('id')
#         blacklist = FirewallBlackListStrategy.objects.filter(device=device).latest('id')
#         device.strategy_apply_status = Device.STRATEGY_APPLY_STATUS_APPLIED
#         device.save()
#         blacklist.save()
#         device_after_signal = Device.objects.get(id=blacklist.device_id)
#         assert device_after_signal.strategy_apply_status is Device.STRATEGY_APPLY_STATUS_UN_APPLIED
