import random

import factory
from factory import fuzzy
from faker import Faker

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from snmp.models import SNMPRule, SNMPTemplate, SNMPSetting, SNMPData
from utils.base_tezt_data import BaseFactory

fake = Faker()


OID_SAMPLES = [
    '.1.3.6.1.4.1.2021.13.15.1.1.2',
    '.1.3.6.1.4.1.2021.13.15.1.1.5',
    '.1.3.6.1.4.1.2021.13.15.1.1.6',
    '.1.3.6.1.2.1.25.3.3.1.2',
]


class BaseRuleFactory(BaseFactory):
    category = fuzzy.FuzzyChoice([i[0] for i in Device.CATEGORY_CHOICE])
    type = fuzzy.FuzzyChoice([i[0] for i in Device.DEV_TEMP_TYPE_CHOICES])
    brand = factory.Faker('text', max_nb_chars=10)
    hardware = factory.Faker('text', max_nb_chars=10)
    add = fuzzy.FuzzyChoice([i[0] for i in SNMPRule.ADD_TYPE_CHOICES])
    update_time = factory.Faker('date_time')


class SNMPRuleFactory(BaseRuleFactory):
    category = fuzzy.FuzzyChoice([i[0] for i in SNMPRule.CATEGORY_CHOICES])
    type = fuzzy.FuzzyChoice([i[0] for i in SNMPRule.TYPE_CHOICES])
    name = factory.Sequence(lambda n: 'SNMPR{}'.format(n))
    oid = factory.LazyFunction(
        lambda: random.sample(OID_SAMPLES, random.randint(1, len(OID_SAMPLES))))
    field = factory.Faker('text', max_nb_chars=20)
    description = factory.Faker('text', max_nb_chars=20)

    class Meta:
        model = SNMPRule


class SNMPTemplateFactory(BaseRuleFactory):
    name = factory.Sequence(lambda n: 'SNMPT{}'.format(n))

    @factory.post_generation
    def rules(self, create, extracted, **kwargs):
        if not create:
            return
        if extracted:
            for rule in extracted:
                self.rules.add(rule)

    class Meta:
        model = SNMPTemplate


class SNMPSettingFactory(BaseFactory):
    device = factory.SubFactory(DeviceFactory)
    version = fuzzy.FuzzyChoice([i[0] for i in SNMPSetting.SNMP_VERSIONS])
    frequency = fuzzy.FuzzyInteger(1, 10)
    overtime = fuzzy.FuzzyInteger(1, 10)
    username = factory.Faker('text', max_nb_chars=20)
    port = fuzzy.FuzzyInteger(1, 100)
    security_level = fuzzy.FuzzyChoice([i[0] for i in SNMPSetting.SECURITY_LEVELS])
    auth = fuzzy.FuzzyChoice([i[0] for i in SNMPSetting.AUTH_PROTOCOLS])
    auth_password = factory.Faker('password')
    priv = fuzzy.FuzzyChoice([i[0] for i in SNMPSetting.PRIV_PROTOCOLS])
    priv_password = factory.Faker('password')
    template = factory.SubFactory(SNMPTemplateFactory)

    class Meta:
        model = SNMPSetting


class SNMPDataFactory(BaseFactory):
    device = factory.SubFactory(DeviceFactory)
    system_info = factory.Faker('text', max_nb_chars=20)
    hostname = factory.Faker('text', max_nb_chars=20)
    system_runtime = factory.Faker('text', max_nb_chars=20)
    disk_info = [{'name': 'loop0', 'read': 0.0, 'write': 0.0}]
    cpu_in_use = fuzzy.FuzzyInteger(0, 100)
    disk_in_use = fuzzy.FuzzyInteger(0, 100)
    disk_total = fuzzy.FuzzyInteger(100, 2000)
    disk_used = fuzzy.FuzzyInteger(100, 2000)
    network_in_speed = fuzzy.FuzzyInteger(0, 100)
    network_out_speed = fuzzy.FuzzyInteger(0, 100)
    network_usage = [{'name': 'enp7s0', 'in': 0.0, 'out': 0.0}]
    cpu_cores = fuzzy.FuzzyInteger(1, 16)
    process_count = fuzzy.FuzzyInteger(20, 100)
    total_memory = fuzzy.FuzzyInteger(1000, 2000)
    memory_used = fuzzy.FuzzyInteger(100, 100)
    memory_in_use = fuzzy.FuzzyInteger(1, 100)
    total_swap_memory = fuzzy.FuzzyInteger(1000, 2000)
    swap_memory_used = fuzzy.FuzzyInteger(1000, 2000)
    swap_memory_in_use = fuzzy.FuzzyInteger(1000, 2000)
    partition_usage = [{'name': '/', 'used': 100, 'total': 1000, 'percent': 10}]

    class Meta:
        model = SNMPData
