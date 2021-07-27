import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from base_app.factory_data import DeviceFactory
from snmp.factory_data import SNMPSettingFactory, SNMPDataFactory, \
    SNMPRuleFactory, SNMPTemplateFactory
from snmp.models import *
from snmp.serializers import SNMPSettingSerializer, SNMPTemplateSerializer
from utils.base_testcase import BaseViewTest, authenticate_read_only, \
    config_engineer_permission_create, config_engineer_permission_update, \
    config_engineer_permission_delete
from utils.core.exceptions import CustomError, CustomValidationError


@pytest.mark.django_db
class TestSNMPRuleView(BaseViewTest):
    @authenticate_read_only
    def test_permissions(self, all_client: Dict[str, APIClient], user: str,
                         expect_code: int):
        client = all_client[user]
        rule = SNMPRuleFactory.create()
        template = SNMPTemplateFactory.create(rules=[rule])
        device = DeviceFactory.create(strategy_apply_status=1)
        SNMPSettingFactory.create(device=device)
        SNMPDataFactory.create(device=device)

        targets = ['snmprule-list', 'snmprule-detail', 'snmptemplate-list',
                   'snmptemplate-detail', 'device-manage-snmp-setting',
                   'device-manage-snmp-data']
        args = [None, rule.id, None, template.id, device.id, device.id]

        for i in range(len(targets)):
            if args[i]:
                response = client.get(reverse(targets[i], args=(args[i],)))
            else:
                response = client.get(reverse(targets[i]))
            assert response.status_code == expect_code

    @config_engineer_permission_create
    def test_create_permission(self, all_client: Dict[str, APIClient],
                               user: str,
                               expect_code: int):
        client = all_client[user]

        rules = SNMPRuleFactory.create_batch(20)
        data = dict(
            name='test',
            type=1,
            category=1,
            rules=[r.id for r in rules]
        )

        response = client.post(
            reverse('snmptemplate-list'),
            data=data,
            format='json',
        )
        assert response.status_code == expect_code

    @config_engineer_permission_update
    def test_update_permission(self, all_client: Dict[str, APIClient],
                               user: str, expect_code: int):
        client = all_client[user]

        t = SNMPTemplateFactory.create(rules=SNMPRuleFactory.create_batch(10),
                                       add=SNMPTemplate.MANUAL_ADD)
        t = SNMPTemplate.objects.get(id=t.id)

        response = client.put(
            reverse('snmptemplate-detail', args=(t.id,)),
            data=dict(
                name='tsssss',
                type=t.type,
                category=t.category,
                rules=[r.id for r in t.rules.all()]
            ),
            format='json',
        )
        t = SNMPTemplate.objects.get(id=t.id)

        assert response.status_code == expect_code

        if response.status_code == 200:
            assert t.name == 'tsssss'

        device = DeviceFactory.create(strategy_apply_status=1)
        setting = SNMPSettingFactory.create(device=device)
        s = SNMPSetting.objects.get(id=setting.id)
        serializer = SNMPSettingSerializer(s).data
        serializer['community'] = '123123123'

        response = client.put(
            reverse('device-manage-snmp-setting', args=(device.id,)),
            data=serializer,
            format='json'
        )

        assert response.status_code == expect_code

        s = SNMPSetting.objects.get(id=s.id)
        if response.status_code == 200:
            assert s.community == serializer['community']

    @config_engineer_permission_delete
    def test_delete_permission(self, all_client: Dict[str, APIClient],
                               user: str, expect_code: int):
        client = all_client[user]

        t = SNMPTemplateFactory.create(add=SNMPTemplate.MANUAL_ADD)

        response = client.delete(
            reverse('snmptemplate-detail', args=(t.id,))
        )

        assert response.status_code == expect_code

    def test_search_rule(self, config_client: APIClient):
        rules = SNMPRuleFactory.create_batch(20, category=1, type=1)
        rule = SNMPRule.objects.get(id=rules[0].id)
        rule.name = 'jjjjjjj'
        rule.brand = 'nnoooo'
        rule.hardware = 'heiheihei'
        rule.save()

        response = config_client.get(
            reverse('snmprule-list'),
            data=dict(
                name='jjj',
                brand='oooo',
                hardware='heihei',
                category=1,
                type=1,
                page=1,
            ),
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data['count'] == 1


class TestTemplateView(BaseViewTest):
    def test_delete_template(self, config_client: APIClient):
        """
        系统内置模板不能删除
        """
        t = SNMPTemplateFactory.create(add=SNMPTemplate.SYSTEM_ADD)

        response = config_client.delete(
            reverse('snmptemplate-detail', args=(t.id,)),
        )

        assert response.status_code == CustomError.status_code
        assert response.data['error'] == \
               str(CustomError.UN_ALLOWED_TO_DELETE_SYSTEM_TEMPLATE)

        t = SNMPTemplateFactory.create(add=SNMPTemplate.MANUAL_ADD)
        response = config_client.delete(
            reverse('snmptemplate-detail', args=(t.id,)),
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_update_template(self, config_client: APIClient):
        t = SNMPTemplateFactory.create(add=SNMPTemplate.SYSTEM_ADD)
        t = SNMPTemplate.objects.get(id=t.id)

        data = SNMPTemplateSerializer(t).data
        data['name'] = 123123

        response = config_client.put(
            reverse('snmptemplate-detail', args=(t.id,)),
            data=data,
            format='json'
        )

        assert response.status_code == CustomError.status_code
        assert response.data['error'] == \
               str(CustomError.UN_ALLOWED_TO_EDIT_SYSTEM_TEMPLATE)

        t = SNMPTemplateFactory.create(add=SNMPTemplate.MANUAL_ADD)
        t = SNMPTemplate.objects.get(id=t.id)
        rules = SNMPRuleFactory.create_batch(20)

        data = SNMPTemplateSerializer(t).data
        data['name'] = 123123
        data['rules'] = [r.id for r in rules]

        response = config_client.put(
            reverse('snmptemplate-detail', args=(t.id,)),
            data=data,
            format='json'
        )

        assert response.status_code == status.HTTP_200_OK

    def test_search_template(self, config_client: APIClient):
        rules = SNMPRuleFactory.create_batch(20)
        templates = SNMPTemplateFactory.create_batch(20, type=1, category=1,
                                                     rules=rules)
        t = SNMPTemplate.objects.get(id=templates[0].id)
        t.name = 'jjjjjjj'
        t.brand = 'nnoooo'
        t.hardware = 'heiheihei'
        t.save()

        response = config_client.get(
            reverse('snmptemplate-list'),
            data=dict(
                name='jjj',
                brand='oooo',
                hardware='heihei',
                category=1,
                type=1,
                page=1,
            ),
            format='json'
        )
        assert response.status_code == status.HTTP_200_OK
        assert response.data['count'] == 1

    def test_get_template_no_page(self, config_client: APIClient):
        SNMPTemplateFactory.create_batch(20)

        response = config_client.get(
            reverse('snmptemplate-list'),
        )

        assert len(response.data) == SNMPTemplate.objects.count()

    def test_create_duplicated_template(self, config_client: APIClient):
        rules = SNMPRuleFactory.create_batch(20)
        template = SNMPTemplateFactory.create(type=1, category=1, rules=rules,
                                               name='123')

        response = config_client.post(
            reverse('snmptemplate-list'),
            data=dict(
                name='123',
                type=1,
                category=1,
                rules=[r.id for r in rules]
            )
        )
        assert response.data == CustomValidationError(
            CustomValidationError.REPEATED_NAME_CATEGORY_TYPE_ERROR).detail

    def test_update_duplicated_template(self, config_client: APIClient):
        """
        修改模板时，name，category，type要和其他模板不同，但是不能影响到自己的修改
        """
        rules = SNMPRuleFactory.create_batch(20)
        template = SNMPTemplateFactory.create(
            type=1, category=1, rules=rules, name='123',
            add=SNMPTemplate.MANUAL_ADD)
        serializer = SNMPTemplateSerializer(template)
        data = serializer.data

        # 修改同一个模板时，禁止重名机制不用生效
        response = config_client.put(
            reverse('snmptemplate-detail', args=(template.id, )),
            data=data,
            format='json'
        )

        assert response.status_code == status.HTTP_200_OK

        # 在已存在一个模板，然后另一个模板也要修改名字和原来的模板一样时，需要报错
        template = SNMPTemplateFactory.create(
            type=1, category=1, rules=rules, name='234',
            add=SNMPTemplate.MANUAL_ADD)
        serializer = SNMPTemplateSerializer(template)
        data = serializer.data
        data['name'] = '123'
        response = config_client.put(
            reverse('snmptemplate-detail', args=(template.id, )),
            data=data,
            format='json',
        )
        assert response.data == CustomValidationError(
            CustomValidationError.REPEATED_NAME_CATEGORY_TYPE_ERROR).detail