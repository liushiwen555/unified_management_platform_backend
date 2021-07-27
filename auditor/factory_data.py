import random

import factory
from django.utils import timezone
from factory import fuzzy

from auditor.models import AuditWhiteListStrategy, AuditorBlackList, \
    AuditBlackListStrategy, AuditIPMACBondStrategy, \
    AuditSecAlert, AuditSysAlert, AuditLog, AttackIPStatistic
from base_app.factory_data import BaseStrategyFactory, TerminalLogFactory
from base_app.models import Device, StrategyTemplate
from utils.base_tezt_data import BaseFactory


def port_pair():
    port1 = random.randint(1, 65535)
    port2 = random.randint(port1, 65535)
    return port1, port2


def ports():
    res = []
    for i in range(random.randint(0, 5)):
        res.append(port_pair())

    return res


class AuditWhiteListStrategyFactory(BaseStrategyFactory):

    name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
    src_ip = factory.Faker('ipv4')
    src_ports = factory.LazyFunction(ports)
    dst_ip = factory.Faker('ipv4')
    dst_ports = factory.LazyFunction(ports)
    protocol = factory.LazyFunction(lambda: random.choice(['tcp', 'udp']))
    rule = factory.Faker('pydict')
    level = factory.LazyFunction(lambda: random.choice([item[0] for item in AuditWhiteListStrategy.LEVEL_CHOICE]))
    is_active = factory.Faker('pybool')
    is_learned = factory.Faker('pybool')
    device = fuzzy.FuzzyChoice(Device.objects.all())
    template = fuzzy.FuzzyChoice(StrategyTemplate.objects.all())

    class Meta:
        model = AuditWhiteListStrategy

    @classmethod
    def stub(cls, *args, **kwargs):
        res = super(AuditWhiteListStrategyFactory, cls).stub(*args, **kwargs)
        res.src_ports = ','.join(
            [str(i[0]) if i[0] == i[1] else ':'.join([str(i[0]), str(i[1])]) for i in res.src_ports])
        res.dst_ports = ','.join(
            [str(i[0]) if i[0] == i[1] else ':'.join([str(i[0]), str(i[1])]) for i in res.dst_ports])
        return res


class AuditorBlackListFactory(BaseFactory):
    sid = factory.Sequence(lambda i: i + 1000000)
    rule = factory.Faker('text', max_nb_chars=20)
    level = factory.LazyFunction(lambda: random.choice(
        [item[0] for item in AuditorBlackList.LEVEL_CHOICE]))
    category = factory.Faker('text', max_nb_chars=18)
    name = factory.Faker('text', max_nb_chars=80)
    description = factory.Faker('text', max_nb_chars=8000)
    vulnerable = factory.Faker('text', max_nb_chars=8000)
    requirement = factory.Faker('text', max_nb_chars=80)
    effect = factory.Faker('text', max_nb_chars=80)
    suggest = factory.Faker('text', max_nb_chars=8000)
    cve = factory.Faker('text', max_nb_chars=18)
    cnnvd = factory.Faker('text', max_nb_chars=18)
    source = factory.LazyFunction(lambda: random.choice(
        [item[0] for item in AuditorBlackList.SOURCE_CHOICE]))
    publish_date = factory.Faker('past_datetime',
                                 tzinfo=timezone.get_default_timezone())
    is_active = factory.Faker('pybool')

    class Meta:
        model = AuditorBlackList


class AuditBlackListStrategyFactory(AuditorBlackListFactory):
    created_time = factory.Faker('past_datetime',
                                 tzinfo=timezone.get_default_timezone())
    edit_time = factory.Faker('past_datetime',
                              tzinfo=timezone.get_default_timezone())
    device = fuzzy.FuzzyChoice(Device.objects.all())
    template = fuzzy.FuzzyChoice(StrategyTemplate.objects.all())

    class Meta:
        model = AuditBlackListStrategy


class AuditIPMACBondStrategyFactory(BaseStrategyFactory):

    name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
    ip = factory.Faker('ipv4')
    mac = factory.Faker('mac_address')
    ip_mac_bond = factory.Faker('pybool')

    class Meta:
        model = AuditIPMACBondStrategy


class AuditSecAlertFactory(TerminalLogFactory):

    category = factory.LazyFunction(lambda: random.choice(
        [i[0] for i in AuditSecAlert.CATEGORY_CHOICE]))
    level = factory.LazyFunction(lambda: random.choice(
        [i[0] for i in AuditSecAlert.LEVEL_CHOICE]))
    src_ip = factory.Faker('ipv4')
    src_port = factory.LazyFunction(lambda: random.randint(1, 65535))
    dst_ip = factory.Faker('ipv4')
    dst_port = factory.LazyFunction(lambda: random.randint(1, 65535))
    protocol = factory.LazyFunction(lambda: random.choice(['tcp', 'udp']))
    device_ip = factory.LazyAttribute(
        lambda o: random.choices([o.src_ip, o.dst_ip], k=random.randint(0, 2)))
    illegal_ip = factory.LazyAttribute(
        lambda o: list({o.src_ip, o.dst_ip} - set(o.device_ip)))
    illegal_port = factory.LazyAttribute(lambda o: random.choices(
        [o.src_port, o.dst_port], k=random.randint(0, 2)))
    first_at = factory.Faker('past_datetime',
                             tzinfo=timezone.get_default_timezone())
    last_at = factory.LazyAttribute(
        lambda o: factory.Faker('date_time_between_dates',
                                datetime_start=o.first_at,
                                tzinfo=timezone.get_default_timezone()).generate({}))
    other_info = factory.Faker('pydict')

    class Meta:
        model = AuditSecAlert


class AuditSysAlertFactory(TerminalLogFactory):
    category = factory.LazyFunction(lambda: random.choice([i[0] for i in AuditSysAlert.CATEGORY_CHOICE]))
    level = factory.LazyFunction(lambda: random.choice([i[0] for i in AuditSysAlert.LEVEL_CHOICE]))

    class Meta:
        model = AuditSysAlert


class AuditLogFactory(TerminalLogFactory):

    category = factory.LazyFunction(lambda: random.choice([i[0] for i in AuditLog.CATEGORY_CHOICE]))
    user = factory.Faker('name', locale='zh_CN')
    ip = factory.Faker('ipv4')

    class Meta:
        model = AuditLog


class AttackIPStatisticFactory(BaseFactory):
    count = fuzzy.FuzzyInteger(100, 1000)
    src_ip = fuzzy.FuzzyInteger(100, 1000)
    foreign = fuzzy.FuzzyInteger(100, 1000)
    external_ip = fuzzy.FuzzyInteger(100, 1000)

    class Meta:
        model = AttackIPStatistic
