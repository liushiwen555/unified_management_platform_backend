from typing import List

import pytest

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from snmp.factory_data import SNMPSettingFactory, SNMPTemplateFactory, \
    SNMPRuleFactory
from snmp.models import SNMPRule, SNMPTemplate, SNMPSetting
from snmp.snmp_run import SNMPClient, snmp_config

rules_factory = [
    {
        "id": 9,
        "name": "网络流速",
        "oid": [
            ".1.3.6.1.2.1.31.1.1.1.1",
            ".1.3.6.1.2.1.2.2.1.10",
            ".1.3.6.1.2.1.2.2.1.16"
        ],
        "field": "network_usage"
    },
    {
        "id": 8,
        "name": "分区利用率",
        "oid": [
            ".1.3.6.1.4.1.2021.9.1.2",
            ".1.3.6.1.4.1.2021.9.1.6",
            ".1.3.6.1.4.1.2021.9.1.8"
        ],
        "field": "partition_usage"
    },
    {
        "id": 7,
        "name": "内存利用率",
        "oid": [
            ".1.3.6.1.4.1.2021.4.5.0",
            ".1.3.6.1.4.1.2021.4.6.0",
            ".1.3.6.1.4.1.2021.4.14.0",
            ".1.3.6.1.4.1.2021.4.15.0",
            ".1.3.6.1.4.1.2021.4.3.0",
            ".1.3.6.1.4.1.2021.4.4.0"
        ],
        "field": "memory_usage"
    },
    {
        "id": 6,
        "name": "进程数",
        "oid": [
            ".1.3.6.1.2.1.25.4.2.1.2"
        ],
        "field": "process_count"
    },
    {
        "id": 5,
        "name": "CPU利用率",
        "oid": [
            ".1.3.6.1.2.1.25.3.3.1.2"
        ],
        "field": "cpu_usage"
    },
    {
        "id": 4,
        "name": "磁盘读写",
        "oid": [
            ".1.3.6.1.4.1.2021.13.15.1.1.2",
            ".1.3.6.1.4.1.2021.13.15.1.1.5",
            ".1.3.6.1.4.1.2021.13.15.1.1.6"
        ],
        "field": "disk_info"
    },
    {
        "id": 3,
        "name": "系统运行时间",
        "oid": [
            ".1.3.6.1.2.1.25.1.1.0"
        ],
        "field": "system_runtime"
    },
    {
        "id": 2,
        "name": "主机名",
        "oid": [
            ".1.3.6.1.2.1.1.5.0"
        ],
        "field": "hostname"
    },
    {
        "id": 1,
        "name": "系统信息",
        "oid": [
            ".1.3.6.1.2.1.1.1.0"
        ],
        "field": "system_info"
    }
]

IP = '10.0.4.199'


@pytest.mark.django_db
class TestSNMPClient:
    @pytest.fixture(scope='function')
    def rules(self) -> List[SNMPRule]:
        result = []
        for i in rules_factory:
            result.append(
                SNMPRuleFactory.create(oid=i['oid'], field=i['field'])
            )
        return result

    @pytest.fixture(scope='function')
    def template(self, rules: List[SNMPRule]) -> SNMPTemplate:
        t = SNMPTemplateFactory.create(rules=rules)
        return t

    @pytest.fixture(scope='function')
    def device(self, template: SNMPTemplate) -> Device:
        device = DeviceFactory.create(strategy_apply_status=1, ip=IP)
        SNMPSettingFactory(device=device, community='test',
                           version=SNMPSetting.SNMP_V2, port=161,
                           template=template)
        return device

    def test_snmp_get_community(self, device: Device):
        device.status = Device.OFFLINE
        device.save()

        client = SNMPClient(device, interval=0)
        res = client.snmp_get()
        assert res != {}
        client.save_data()

    def test_snmp_get_no_response(self, device: Device):
        s = device.snmpsetting
        device.ip = '11.1.1.1'
        device.save()
        s.save()
        client = SNMPClient(device, interval=0)
        res = client.snmp_get()
        assert res == {}
        client.save_data()

        device = Device.objects.get(id=device.id)
        assert device.status == Device.OFFLINE

    def test_snmp_get_wrong_community(self, device: Device):
        s = device.snmpsetting
        s.community = 'tesss'
        device.save()
        s.save()
        client = SNMPClient(device, interval=0)
        res = client.snmp_get()
        assert res == {}
        client.save_data()

    def test_snmp_get_no_auth_no_priv(self, device: Device):
        setting = device.snmpsetting
        setting.version = setting.SNMP_V3
        setting.username = 'testuser'
        setting.security_level = setting.NO_AUTH_NO_PRIV
        setting.save()

        client = SNMPClient(device, interval=0)
        res = client.snmp_get()
        assert res != {}

    def test_snmp_get_auth_no_priv(self, device: Device):
        setting = device.snmpsetting
        setting.version = setting.SNMP_V3
        setting.username = 'myname'
        setting.security_level = setting.AUTH_NO_PRIV
        setting.auth_password = 'mypassword'
        setting.auth = setting.AUTH_MD5
        setting.save()

        client = SNMPClient(device, interval=0)
        res = client.snmp_get()
        assert res != {}

    def test_snmp_get_auth_priv(self, device: Device):
        setting = device.snmpsetting
        setting.version = setting.SNMP_V3
        setting.username = 'bolean'
        setting.security_level = setting.AUTH_PRIV
        setting.auth_password = '12345678'
        setting.auth = setting.AUTH_MD5
        setting.priv_password = '87654321'
        setting.priv = setting.PRIV_AES128
        setting.save()

        client = SNMPClient(device, interval=0)
        res = client.snmp_get()
        assert res != {}

    def test_device_active(self, device: Device):
        client = SNMPClient(device)
        assert client.is_device_active()

        device.ip = '1.11.11.1'
        device.save()

        client = SNMPClient(device)
        assert client.is_device_active() is False
        res = client.snmp_get()
        assert res == {}


class TestSNMPConfig:
    def test_register_config(self):
        @snmp_config.register(['1234'], 'walk', 'test')
        class TestConfig:
            pass

        assert snmp_config.get_config('test') == \
               {'method': 'walk', 'client': TestConfig, 'oid': ['1234']}
