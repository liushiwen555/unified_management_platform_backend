from abc import ABC, abstractmethod

import pytest
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIClient

from log.models import UnifiedForumLog
from utils.base_testcase import BaseUser


User = get_user_model()


@pytest.mark.django_db
class BaseLogTest(ABC):
    type = None
    category = None

    @abstractmethod
    def format_content(self, *args, **kwargs):
        pass

    @pytest.fixture(scope='function')
    def client(self):
        client = APIClient()
        return client

    @pytest.fixture(scope='function')
    def admin_client(self):
        client = APIClient()
        client.force_authenticate(user=User.objects.get(
            username=BaseUser.admin_name))
        return client

    @pytest.fixture(scope='function')
    def config_client(self):
        client = APIClient()
        client.force_authenticate(user=User.objects.get(
            username=BaseUser.config_engineer_name))
        return client

    @pytest.fixture(scope='function')
    def audit_client(self):
        client = APIClient()
        client.force_authenticate(user=User.objects.get(
            username=BaseUser.auditor_name))
        return client

    @pytest.fixture(scope='function')
    def engineer_client(self):
        client = APIClient()
        client.force_authenticate(user=User.objects.get(
            username=BaseUser.engineer_name))
        return client

    def check_type_and_category(self, log: UnifiedForumLog):
        assert log.type == self.type
        assert log.category == self.category

    @staticmethod
    def status_desc(status_code: int):
        if status.is_success(status_code):
            return '成功'
        else:
            return '失败'

    def get_queryset(self):
        return UnifiedForumLog.objects.filter(
            category=self.category, type=self.type)