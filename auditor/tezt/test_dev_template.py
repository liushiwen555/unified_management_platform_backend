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
# from auditor.models import AuditBlackListStrategy, AuditorBlackList, AuditWhiteListStrategy, AuditIPMACBondStrategy
# from base_app.factory_data import DeviceFactory, TemplateFactory
# from base_app.models import Device, StrategyTemplate
# from utils.base_testcase import BaseTest
# from utils.core.permissions import IsSecurityEngineer, IsConfiEngineer
#
# fake = faker.Faker('zh_CN')
#
#
# @pytest.mark.django_db
# class TestAuditorDeviceView(BaseTest):
#
#     url_permission_map = {
#         'device-list': {
#             'get': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#             'post': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#         },
#         'device-detail': {
#             'get': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#             'put': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
#             'patch': {'permission': AllowAny, 'user_identity': ['engineer', 'anonymous', 'admin', 'auditor']},
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
#     }
#
#     @property
#     def factory(self):
#         return DeviceFactory
#
#     @fixture(scope='class')
#     def list_url(self):
#         return reverse('auditor:device-list')
#
#     @fixture(scope='class')
#     def detail_id(self):
#         return Device.objects.filter(type=Device.AUDITOR).latest('id').id
#
#     @fixture(scope='class')
#     def detail_url(self, detail_id):
#         return reverse('auditor:device-detail', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def invalid_detail_url(self):
#         return reverse('auditor:device-detail', kwargs={'pk': sys.maxsize})
#
#     @fixture(scope='class')
#     def batch_operation_url(self):
#         return reverse('auditor:device-batch-operation-list')
#
#     @fixture(scope='class')
#     def clear_unregistered_url(self):
#         return reverse('auditor:device-clear-unregistered-list')
#
#     @fixture(scope='class')
#     def register_url(self):
#         return reverse('auditor:device-register-list')
#
#     @fixture(scope='class')
#     def to_temp_url(self, detail_id):
#         return reverse('auditor:device-to-temp', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def apply_strategies_url(self, detail_id):
#         return reverse('auditor:device-apply-strategies', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def post_data_map(self):
#         return {
#             201: {
#                 'name': [fake.pystr(min_chars=1, max_chars=20)],
#                 'location': [fake.pystr(min_chars=1, max_chars=20)],
#                 'responsible_user': [fake.pystr(min_chars=1, max_chars=32)]
#             },
#             400: {
#                 'name': ['', None, fake.pystr(min_chars=21, max_chars=21)],
#                 'location': ['', None, fake.pystr(min_chars=21, max_chars=21)],
#                 'responsible_user': ['', None, fake.pystr(min_chars=33, max_chars=33)]
#             },
#         }
#
#     @fixture(scope='class')
#     def put_data_map(self):
#         return {
#             200: {
#                 'name': [fake.pystr(min_chars=1, max_chars=20)],
#                 'location': [fake.pystr(min_chars=1, max_chars=20)],
#                 'responsible_user': [fake.pystr(min_chars=1, max_chars=32)],
#                 'template_name': [None, '', fake.pystr(min_chars=1, max_chars=64)]
#             },
#             400: {
#                 'name': ['', None, fake.pystr(min_chars=21, max_chars=21)],
#                 'location': ['', None, fake.pystr(min_chars=21, max_chars=21)],
#                 'responsible_user': ['', None, fake.pystr(min_chars=33, max_chars=33)],
#                 'template_name': [fake.pystr(min_chars=65, max_chars=65)]
#             },
#         }
#
#     def test_signals(self, detail_id):
#         """
#         auditor device creation signal will trigger blacklists created to each device
#         :return:
#         """
#         assert AuditBlackListStrategy.objects.filter(device_id=detail_id).count() == AuditorBlackList.objects.count()
#
#     def test_permissions(self, list_url, detail_url, batch_operation_url, clear_unregistered_url, register_url,
#                          to_temp_url, apply_strategies_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(batch_operation_url, url_permission_map)
#         self.check_permissions(clear_unregistered_url, url_permission_map)
#         self.check_permissions(register_url, url_permission_map)
#         self.check_permissions(to_temp_url, url_permission_map)
#         self.check_permissions(apply_strategies_url, url_permission_map)
#
#
#     # def test_post(self, list_url, post_data_map, user=BaseTest.engineer_name):
#     #     self.tezt_data('post', list_url, user, self.factory, post_data_map)
#     #
#     # def test_put(self, detail_url, put_data_map, user=BaseTest.engineer_name):
#     #     self.tezt_data('put', detail_url, user, self.factory, put_data_map)
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
#         assert Device.objects.filter(type=Device.AUDITOR, status=Device.NOT_REGISTERED).count() == 0
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
#         assert AuditWhiteListStrategy.objects.filter(
#             device_id=detail_id).count() == AuditWhiteListStrategy.objects.filter(template=template).count()
#         assert AuditIPMACBondStrategy.objects.filter(
#             device_id=detail_id).count() == AuditIPMACBondStrategy.objects.filter(template=template).count()
#         assert AuditBlackListStrategy.objects.filter(
#             device_id=detail_id).count() == AuditBlackListStrategy.objects.filter(template=template).count()
#         assert status.is_success(response.status_code)
#
#     def test_device_apply_strategies_url(self, apply_strategies_url, detail_id):
#         """ 设备启用策略 log，当前只能记录响应code 499"""
#         # self.engineer()
#         method = 'post'
#         data = {'pk': detail_id}
#         self.tezt_manage_log(method, apply_strategies_url, data)
#
#
# @pytest.mark.django_db
# class TestAuditorTemplateView(BaseTest):
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
#     }
#
#     @property
#     def factory(self):
#         return TemplateFactory
#
#     @fixture(scope='class')
#     def list_url(self):
#         return reverse('auditor:template-list')
#
#     @fixture(scope='class')
#     def detail_id(self):
#         return StrategyTemplate.objects.filter(type=Device.AUDITOR).latest('id').id
#
#     @fixture(scope='class')
#     def detail_url(self, detail_id):
#         return reverse('auditor:template-detail', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def invalid_detail_url(self):
#         return reverse('auditor:template-detail', kwargs={'pk': sys.maxsize})
#
#     @fixture(scope='class')
#     def to_new_temp_url(self, detail_id):
#         return reverse('auditor:template-to-new-temp', kwargs={'pk': detail_id})
#
#     @fixture(scope='class')
#     def deploy_to_device_url(self, detail_id):
#         return reverse('auditor:template-deploy-to-device', kwargs={'pk': detail_id})
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
#         auditor device creation signal will trigger blacklists created to each device
#         :return:
#         """
#         assert AuditBlackListStrategy.objects.filter(template_id=detail_id).count() == AuditorBlackList.objects.count()
#
#     def test_permissions(self, list_url, detail_url,
#                          to_new_temp_url, deploy_to_device_url):
#         url_permission_map = self.url_permission_map
#
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#         self.check_permissions(to_new_temp_url, url_permission_map)
#         self.check_permissions(deploy_to_device_url, url_permission_map)
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
#         assert AuditWhiteListStrategy.objects.filter(
#             template_id=detail_id).count() == AuditWhiteListStrategy.objects.filter(template=template).count()
#         assert AuditIPMACBondStrategy.objects.filter(
#             template_id=detail_id).count() == AuditIPMACBondStrategy.objects.filter(template=template).count()
#         assert AuditBlackListStrategy.objects.filter(
#             template_id=detail_id).count() == AuditBlackListStrategy.objects.filter(template=template).count()
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
#             assert AuditWhiteListStrategy.objects.filter(
#                 template_id=detail_id).count() == AuditWhiteListStrategy.objects.filter(device=device).count()
#             assert AuditIPMACBondStrategy.objects.filter(
#                 template_id=detail_id).count() == AuditIPMACBondStrategy.objects.filter(device=device).count()
#             assert AuditBlackListStrategy.objects.filter(
#                 template_id=detail_id).count() == AuditBlackListStrategy.objects.filter(device=device).count()
#
#     def test_add_tem_log(self, list_url, post_data_map):
#         """测试添加模板"""
#         method = 'post'
#         data = self.factory.post_data().copy()
#         self.tezt_manage_log(method, list_url, data)
#
#     def get_device_type(self):
#         return Device.AUDITOR
