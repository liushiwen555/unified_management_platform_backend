from typing import Dict

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from log.models import UnifiedForumLog
from log.tests.test_log_generator.base_testcase import BaseLogTest
from unified_log.models import LogProcessRule, LogProcessTemplate
from unified_log.factory_data import LogProcessTemplateFactory, \
    LogProcessRuleFactory
from base_app.factory_data import DeviceFactory
from unified_log.serializers import LogTemplateCreateSerializer


@pytest.mark.django_db
class TestUnifiedTemplateLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_KNOWLEDGE
    category = UnifiedForumLog.CATEGORY_OPERATION
    LIST_TEMPLATE = 'log-template-list'
    DETAIL_TEMPLATE = 'log-template-detail'

    def format_content(self, method: str, id: int, name: str, status_code: int):
        return f'{method}日志监控模板【{name}】, {self.status_desc(status_code)}'

    @pytest.fixture(scope='function')
    def data(self):
        LogProcessRuleFactory.create_batch(10)
        template = LogProcessTemplateFactory.create()
        serializer = LogTemplateCreateSerializer(template)
        data = serializer.data
        data['id'] = template.id
        return data

    def test_add_template(self, config_client: APIClient, data: Dict):
        data = data.copy()
        data['name'] = '1234'
        data.pop('id')

        response = config_client.post(
            reverse(self.LIST_TEMPLATE),
            data=data,
            format='json'
        )
        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '添加', response.data['id'], response.data['name'],
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_delete_template(self, config_client: APIClient):
        LogProcessRuleFactory.create_batch(10)
        template = LogProcessTemplateFactory.create()

        response = config_client.delete(
            reverse(self.DETAIL_TEMPLATE, args=(template.id, ))
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '删除', template.id, template.name, response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_update_template(self, config_client: APIClient, data: Dict):
        response = config_client.put(
            reverse(self.DETAIL_TEMPLATE, args=(data['id'], )),
            data=data,
            format='json',
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '编辑', data['id'], data['name'], response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestUnifiedLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    def format_content(self, id: int, name: str) -> str:
        return '设置【{id}-{name}】的日志监控'.format(id=id, name=name)

    def test_unified_log_setting(self, config_client):
        device = DeviceFactory.create_normal()
        LogProcessRuleFactory.create_batch(10)
        template = LogProcessTemplateFactory.create()

        response = config_client.put(
            reverse('device-manage-log-setting', args=(device.id, )),
            data=dict(
                log_status=False,
                log_template=template.id,
            ),
            format='json'
        )
        content = self.format_content(device.id, device.name)
        log = UnifiedForumLog.objects.filter(
            content=self.format_content(device.id, device.name)
        )
        assert log.exists()
        self.check_type_and_category(log[0])