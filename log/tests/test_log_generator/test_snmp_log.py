from typing import Dict

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from log.models import UnifiedForumLog
from log.tests.test_log_generator.base_testcase import BaseLogTest
from base_app.factory_data import DeviceFactory
from snmp.factory_data import SNMPTemplateFactory, SNMPRuleFactory,\
    SNMPSettingFactory
from snmp.serializers import SNMPTemplateSerializer, SNMPSettingSerializer


@pytest.mark.django_db
class TestSNMPTemplateLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_KNOWLEDGE
    category = UnifiedForumLog.CATEGORY_OPERATION

    LIST_TEMPLATE = 'snmptemplate-list'
    DETAIL_TEMPLATE = 'snmptemplate-detail'

    def format_content(self, method: str, name: str, status_code: int):
        return f'{method}性能监控模板【{name}】, {self.status_desc(status_code)}'

    @pytest.fixture(scope='function')
    def data(self):
        rules = SNMPRuleFactory.create_batch(4)
        template = SNMPTemplateFactory.create(rules=rules)
        serializer = SNMPTemplateSerializer(template)
        data = serializer.data
        data['id'] = template.id
        return data

    def test_add_template(self, config_client: APIClient, data: Dict):
        data = data.copy()
        data['name'] = '1234'
        response = config_client.post(
            reverse(self.LIST_TEMPLATE),
            data=data,
            format='json'
        )
        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '添加', response.data['name'], response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_delete_template(self, config_client: APIClient):
        template = SNMPTemplateFactory.create()

        response = config_client.delete(
            reverse(self.DETAIL_TEMPLATE, args=(template.id, ))
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '删除', template.name, response.status_code
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
            '编辑', data['name'], response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestSNMPSettingLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_ASSETS
    category = UnifiedForumLog.CATEGORY_OPERATION

    DETAIL_SETTING = 'device-manage-snmp-setting'

    def format_content(self, id: int, name: str, status_code: int):
        return f'设置【{id} - {name}】的性能监控, {self.status_desc(status_code)}'

    def test_update_setting(self, config_client: APIClient):
        device = DeviceFactory.create_normal()
        setting = SNMPSettingFactory.create(device=device)
        data = SNMPSettingSerializer(setting).data
        response = config_client.put(
            reverse(self.DETAIL_SETTING, args=(device.id, )),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            device.id, device.name, response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])
