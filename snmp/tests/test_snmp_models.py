import random

import pytest
from rest_framework.exceptions import ValidationError
from django.db.utils import IntegrityError
from django.db import transaction

from base_app.models import Device
from base_app.factory_data import DeviceFactory
from snmp.models import SNMPRule, SNMPTemplate, SNMPSetting, SNMPData
from snmp.factory_data import OID_SAMPLES, SNMPRuleFactory, SNMPTemplateFactory,\
    SNMPSettingFactory


@pytest.mark.django_db
class TestSNMPRule:
    def test_save(self):
        rule = SNMPRule(name='hello', category=1, type=1,
                        oid=random.sample(OID_SAMPLES, 1), field='hello')
        rule.save()
        print(rule)
        assert rule.id is not None

    def test_duplicate_name(self):
        """
        同个category和type下，name不能重复
        """
        rule = SNMPRule(name='123', category=1, type=1,
                        oid=random.sample(OID_SAMPLES, 1), field='hello')
        rule.save()

        with pytest.raises(IntegrityError):
            rule = SNMPRule(name='123', category=1, type=1,
                            oid=random.sample(OID_SAMPLES, 1), field='hello')
            with transaction.atomic():
                rule.save()
        rule = SNMPRule(name='123', category=1, type=2,
                        oid=random.sample(OID_SAMPLES, 1), field='hello')
        rule.save()

        assert rule.id is not None


@pytest.mark.django_db
class TestSNMPTemplate:
    def test_factory_save(self):
        rules = SNMPRuleFactory.create_batch(20)
        template = SNMPTemplateFactory.create(rules=rules)
        t = SNMPTemplate.objects.get(id=template.id)
        r = SNMPRule.objects.get(id=rules[0].id)

        print(t)
        assert t.rules.count() == 20
        assert r.snmptemplate_set.count() == 1

    def test_save(self):
        rules = SNMPRuleFactory.create_batch(20)
        template = SNMPTemplate(name='hello', category=1, type=1)
        template.save()

        template.rules.add(*rules)
        template.save()

        assert template.rules.count() == 20

        # 测试add规则使用id
        template = SNMPTemplate(name='hello1', category=1, type=1)
        template.save()

        template.rules.add(*[i.id for i in rules])
        assert template.rules.count() == 20

    def test_update(self):
        rules = SNMPRuleFactory.create_batch(20)
        template = SNMPTemplateFactory.create(rules=rules)
        t = SNMPTemplate.objects.get(id=template.id)
        rules = SNMPRuleFactory.create_batch(10)

        t.rules.add(*rules)
        t.save()

        assert t.rules.count() == 30

    def test_format_rules(self):
        rule = SNMPRuleFactory.create()
        t = SNMPTemplateFactory.create(rules=[rule])
        t = SNMPTemplate.objects.get(id=t.id)
        format_rules = t.format_rules()

        assert format_rules[0]['name'] == rule.name
        assert format_rules[0]['oid'] == rule.oid

    def test_duplicate_name(self):
        """
        同个category和type下，name不能重复
        """
        t = SNMPTemplate(name='123', category=1, type=1)
        t.save()

        with pytest.raises(IntegrityError):
            t = SNMPTemplate(name='123', category=1, type=1)
            with transaction.atomic():
                t.save()
        t = SNMPTemplate(name='123', category=1, type=2)
        t.save()

        assert t.id is not None


@pytest.fixture(scope='function')
def device() -> Device:
    d = DeviceFactory.create(strategy_apply_status=1)
    d = Device.objects.get(id=d.id)
    return d


@pytest.mark.django_db
class TestSNMPSetting:
    def test_save(self, device: Device):
        setting = SNMPSetting(device=device)
        setting.save()
        print(setting)
        assert setting.id is not None

    def test_save_snmp_v1_v2(self, device: Device):
        with pytest.raises(ValidationError):
            s = SNMPSetting(
                device=device,
                version=SNMPSetting.SNMP_V1,
                community=None
            )
            s.save()

        s.community = 'hello'
        s.save()
        assert s.id is not None

    def test_save_no_auth_no_priv(self, device: Device):
        with pytest.raises(ValidationError):
            s = SNMPSetting(
                device=device,
                version=SNMPSetting.SNMP_V3
            )
            s.save()

        with pytest.raises(ValidationError):
            s = SNMPSetting(
                device=device,
                version=SNMPSetting.SNMP_V3,
                security_level=SNMPSetting.NO_AUTH_NO_PRIV,
            )
            s.save()

        s.username = 'yuhao'
        s.save()

    def test_save_auth_no_priv(self, device: Device):
        with pytest.raises(ValidationError):
            s = SNMPSetting(
                device=device,
                version=SNMPSetting.SNMP_V3,
                security_level=SNMPSetting.AUTH_NO_PRIV,
                username='yuhao'
            )
            s.save()

        s.auth = SNMPSetting.AUTH_MD5
        s.auth_password = '123456'
        s.save()

    def test_save_auth_priv(self, device: Device):
        with pytest.raises(ValidationError):
            s = SNMPSetting(
                device=device,
                version=SNMPSetting.SNMP_V3,
                security_level=SNMPSetting.AUTH_PRIV,
                username='yuhao',
                auth=SNMPSetting.AUTH_MD5,
                auth_password='123456'
            )
            s.save()

        s.priv = SNMPSetting.PRIV_DES
        s.priv_password = '123456'
        s.save()

    def test_check_duplicate_device(self, device: Device):
        SNMPSettingFactory.create(device=device)
        with pytest.raises(ValidationError):
            SNMPSettingFactory.create(device=device)

    def test_delete_device(self):
        device = DeviceFactory()
        s = SNMPSettingFactory(device=device)

        Device.objects.get(id=device.id).delete()
        with pytest.raises(SNMPSetting.DoesNotExist):
            SNMPSetting.objects.get(id=s.id)


@pytest.mark.django_db
class TestSNMPData:
    test_data = {
        'cpu_cores': 4,
        'cpu_in_use': 6,
        'disk_info': [{'name': 'loop0', 'read': 0.0, 'write': 0.0}],
        'hostname': 'bolean',
        'memory_in_use': 97,
        'memory_used': 7633,
        'partition_usage': [
            {'name': '/', 'percent': 0.2, 'total': 1876760.19, 'used': 17824.65}
        ],
        'process_count': 203,
        'swap_memory_in_use': 1,
        'swap_memory_used': 20,
        'system_info': 'Linux bolean 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64',
        'system_runtime': '13天22小时22分钟50秒',
        'total_memory': 7904,
        'total_swap_memory': 2047,
        'network_in_speed': 112,
        'network_out_speed': 298,
        'network_usage': [{'in': 724.0, 'name': 'lo', 'out': 724.0}]
    }

    def test_save(self, device: Device):
        data = SNMPData(**self.test_data, device=device)
        data.save()

        data = SNMPData.objects.get(device=device)

        assert data.system_info == 'Linux bolean 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64'
        assert data.hostname == 'bolean'
        assert data.system_runtime == '13天22小时22分钟50秒'
        assert data.disk_info == [{'name': 'loop0', 'read': 0.0, 'write': 0.0}]
        assert data.cpu_cores == 4
        assert data.cpu_in_use == 6
        assert data.process_count == 203
        assert data.total_memory == 7904
        assert data.memory_used == 7633
        assert data.memory_in_use == 97
        assert data.total_swap_memory == 2047
        assert data.swap_memory_used == 20
        assert data.swap_memory_in_use == 1
        assert data.partition_usage == [
            {'name': '/', 'percent': 0.2, 'total': 1876760.19, 'used': 17824.65}
        ]
        assert data.network_in_speed == 112
        assert data.network_out_speed == 298
        assert data.network_usage == [{'in': 724.0, 'name': 'lo', 'out': 724.0}]

    def test_update(self, device: Device):
        data = SNMPData(**self.test_data, device=device)
        data.save()
        data = SNMPData(**self.test_data, device=device)
        data.save()

        assert SNMPData.objects.filter(device=device).count() == 2

    def test_save_none_data(self, device: Device):
        data = SNMPData(device=device)
        data.save()

        assert data.id is not None

    # def test_save_duplicate(self, device: Device):
    #     data = SNMPData(**self.test_data, device=device)
    #     data.save()
    #
    #     data2 = SNMPData(**self.test_data, device=device)
    #     data2.save()
    #
    #     assert data2.id == data.id
