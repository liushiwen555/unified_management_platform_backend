# import sys
#
# import faker
# import pytest
# from _pytest.fixtures import fixture
# from django.urls import reverse
# from rest_framework import status
#
# from auditor.factory_data import AuditSecAlertFactory
# from auditor.models import AuditSecAlert
# from utils.base_testcase import BaseTest
# from utils.core.permissions import IsConfiEngineer
#
# fake = faker.Faker('zh_CN')
#
#
# @pytest.mark.django_db
# class TestAuditorSecAlertLog(BaseTest):
#     """
#     各个终端部分的安全告警功能测试。
#     主要为：拉取 list，detail，invalid url，read/ unread 等功能。
#     """
#     url_permission_map = {
#         'sec-alert-list': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#         'sec-alert-detail': {
#             'get': {'permission': IsConfiEngineer, 'user_identity': ['engineer', 'auditor']},
#         },
#     }
#
#     @property
#     def factory(self):
#         return AuditSecAlertFactory
#
#     @fixture(scope='class')
#     def list_url(self):
#         return reverse('auditor:sec-alert-list')
#
#     @fixture(scope='class')
#     def detail_url(self):
#         audit_sec_detail_id = AuditSecAlert.objects.latest('id').id
#         args = []
#         args.append(audit_sec_detail_id)
#         return reverse('auditor:sec-alert-detail', args=args)
#
#     @fixture(scope='class')
#     def invalid_detail_url(self):
#         invalid_detail_args = []
#         invalid_detail_args.append(str(sys.maxsize))
#         return reverse('auditor:sec-alert-detail', args=invalid_detail_args)
#
#     def test_permissions(self, list_url, detail_url):
#         url_permission_map = self.url_permission_map
#         self.check_permissions(list_url, url_permission_map)
#         self.check_permissions(detail_url, url_permission_map)
#
#     def test_get_list(self, list_url, user='engineer'):
#
#         count = self.list_size ** 2
#         getattr(self, user)()
#         response = self.client.get(list_url)
#         assert response.status_code == status.HTTP_200_OK
#         assert response.data['count'] == count
#
#         response = self.client.get(list_url, {'page': 1, 'page_size': self.page_size})
#
#         assert response.status_code == status.HTTP_200_OK
#         assert response.data['count'] == count
#         assert response.data['page_count'] == count/self.page_size
#
#     def test_get_detail(self, detail_url, user='engineer'):
#
#         getattr(self, user)()
#         response = self.client.get(detail_url)
#         assert response.status_code == status.HTTP_200_OK
#
#     def test_get_detail_404(self, invalid_detail_url, user='engineer'):
#         getattr(self, user)()
#         response = self.client.get(invalid_detail_url)
#         assert response.status_code == status.HTTP_404_NOT_FOUND
#
#     def test_read_unread(self, list_url, user='engineer'):
#         """测试是否已读"""
#         getattr(self, user)()
#         unread_url = list_url + 'unread/'
#         response = self.client.get(unread_url)
#         unread_from_response = response.data['unread']
#         count_unread = AuditSecAlert.objects.filter(is_read=False).count()
#         assert count_unread == unread_from_response
#
#     def test_delete(self):
#         """无测试需求"""
#         pass
