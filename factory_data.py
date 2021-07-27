import random

import factory
from django.utils import timezone

from base_app.factory_data import BaseStrategyFactory, TerminalLogFactory
from firewall.models import ConfStrategy, BaseFirewallStrategy, FirewallWhiteListStrategy, \
    FirewallLearnedWhiteListStrategy, IndustryProtocolDefaultConfStrategy, IndustryProtocolOPCStrategy, \
    IndustryProtocolModbusStrategy, IndustryProtocolS7Strategy, FirewallBlackList, FirewallBlackListStrategy, \
    FirewallIPMACBondStrategy, FirewallIPMACUnknownDeviceActionStrategy, FirewallSecEvent, FirewallSysEvent, \
    ACTION_CHOICES, STATUS_CHOICES, LOGGING_CHOICES
from utils.base_tezt_data import BaseFactory


# class FirewallTerminalLogFactory(BaseLogFactory):
#
#     @factory.post_generation
#     def device(self, create, extracted, **kwargs):
#
#         if extracted:
#             self.device = extracted
#         elif Device.objects.filter(type=Device.FIRE_WALL).exists():
#             self.device = random.choice(Device.objects.filter(type=Device.FIRE_WALL))


# class FirewallStrategyFactory(BaseStrategyFactory):
#
#     @factory.post_generation
#     def device(self, create, extracted, **kwargs):
#
#         if extracted:
#             self.device = extracted
#         elif Device.objects.filter(type=Device.FIRE_WALL).exists():
#             self.device = random.choice(Device.objects.filter(type=Device.FIRE_WALL))
#
#     @factory.post_generation
#     def template(self, create, extracted, **kwargs):
#
#         if extracted:
#             self.template = extracted
#         elif StrategyTemplate.objects.filter(type=Device.FIRE_WALL).exists():
#             self.template = random.choice(StrategyTemplate.objects.filter(type=Device.FIRE_WALL))


class ConfStrategyFactory(BaseStrategyFactory):
    run_mode = factory.LazyFunction(lambda: random.choice([i[0] for i in ConfStrategy.RUN_MODE_CHOICES]))
    default_filter = factory.LazyFunction(lambda: random.choice([i[0] for i in ConfStrategy.DEFAULT_FILTER_CHOICES]))
    DPI = factory.LazyFunction(lambda: random.choice([i[0] for i in ConfStrategy.DPI_CHOICES]))

    class Meta:
        model = ConfStrategy


class BaseFirewallStrategyFactory(BaseStrategyFactory):
    rule_id = factory.Sequence(lambda n: n)
    rule_name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
    src_ip = factory.Faker('ipv4')
    dst_ip = factory.Faker('ipv4')
    src_port = factory.LazyFunction(lambda: random.randint(1, 65535))
    dst_port = factory.LazyFunction(lambda: random.randint(1, 65535))
    protocol = factory.LazyFunction(lambda: random.choice(['tcp', 'udp']))
    action = factory.LazyFunction(lambda: random.choice([i[0] for i in ACTION_CHOICES]))
    status = factory.LazyFunction(lambda: random.choice([i[0] for i in STATUS_CHOICES]))
    logging = factory.LazyFunction(lambda: random.choice([i[0] for i in LOGGING_CHOICES]))

    class Meta:
        model = BaseFirewallStrategy


class FirewallWhiteListStrategyFactory(BaseStrategyFactory):
    rule_id = factory.Sequence(lambda n: n)
    rule_name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
    src_ip = factory.Faker('ipv4')
    dst_ip = factory.Faker('ipv4')
    src_port = factory.LazyFunction(lambda: random.randint(1, 65535))
    dst_port = factory.LazyFunction(lambda: random.randint(1, 65535))
    protocol = factory.LazyFunction(lambda: random.choice(['tcp', 'udp']))
    action = factory.LazyFunction(lambda: random.choice([i[0] for i in ACTION_CHOICES]))
    status = factory.LazyFunction(lambda: random.choice([i[0] for i in STATUS_CHOICES]))
    logging = factory.LazyFunction(lambda: random.choice([i[0] for i in LOGGING_CHOICES]))

    class Meta:
        model = FirewallWhiteListStrategy


class FirewallLearnedWhiteListStrategyFactory(BaseStrategyFactory):
    sid = factory.Sequence(lambda n: n)
    fields = factory.Faker('text', locale='en_us', max_nb_chars=100)
    level = factory.LazyFunction(lambda: random.choice([i[0] for i in FirewallLearnedWhiteListStrategy.LEVEL_CHOICE]))
    rule_name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
    src_ip = factory.Faker('ipv4')
    dst_ip = factory.Faker('ipv4')
    src_mac = factory.Faker('mac_address')
    dst_mac = factory.Faker('mac_address')
    proto = factory.LazyFunction(lambda: random.choice(['tcp', 'udp']))
    tmp_action = factory.LazyFunction(
        lambda: random.choice([i[0] for i in FirewallLearnedWhiteListStrategy.LEARNED_WHITELIST_ACTION_CHOICES]))
    action = factory.LazyFunction(
        lambda: random.choice([i[0] for i in FirewallLearnedWhiteListStrategy.LEARNED_WHITELIST_ACTION_CHOICES]))
    proto_name = factory.LazyFunction(lambda: random.choice(['tcp', 'udp']))
    status = factory.LazyFunction(lambda: random.choice([i[0] for i in STATUS_CHOICES]))

    class Meta:
        model = FirewallLearnedWhiteListStrategy


class IndustryProtocolDefaultConfStrategyFactory(BaseStrategyFactory):
    OPC_default_action = factory.LazyFunction(lambda: random.choice([i[0] for i in STATUS_CHOICES]))
    modbus_default_action = factory.LazyFunction(lambda: random.choice([i[0] for i in STATUS_CHOICES]))

    class Meta:
        model = IndustryProtocolDefaultConfStrategy


class IndustryProtocolOPCStrategyFactory(BaseStrategyFactory):
    is_read_open = factory.Faker('pybool')
    read_action = factory.LazyFunction(
        lambda: random.choice([i[0] for i in IndustryProtocolOPCStrategy.READ_WRITE_ACTION_CHOICES]))
    is_write_open = factory.Faker('pybool')
    write_action = factory.LazyFunction(
        lambda: random.choice([i[0] for i in IndustryProtocolOPCStrategy.READ_WRITE_ACTION_CHOICES]))

    class Meta:
        model = IndustryProtocolOPCStrategy


class IndustryProtocolModbusStrategyFactory(BaseStrategyFactory):
    rule_id = factory.Sequence(lambda n: n)
    rule_name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
    func_code = factory.Faker('text', locale='en_us', max_nb_chars=20)
    reg_start = factory.LazyFunction(lambda: random.randint(64, 1400))
    reg_end = factory.LazyAttribute(lambda o: str(int(o.reg_start) + random.randint(10, 100)))
    reg_value = factory.LazyAttribute(lambda o: str(int(o.reg_end) - int(o.reg_start)))
    length = factory.LazyFunction(lambda: random.randint(64, 1400))
    action = factory.LazyFunction(lambda: random.choice([i[0] for i in ACTION_CHOICES]))
    logging = factory.LazyFunction(lambda: random.choice([i[0] for i in LOGGING_CHOICES]))
    status = factory.LazyFunction(lambda: random.choice([i[0] for i in STATUS_CHOICES]))

    class Meta:
        model = IndustryProtocolModbusStrategy


class IndustryProtocolS7StrategyFactory(BaseStrategyFactory):
    rule_id = factory.Sequence(lambda n: n)
    rule_name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
    func_type = factory.Faker('text', locale='en_us', max_nb_chars=64)
    pdu_type = factory.Faker('text', locale='en_us', max_nb_chars=64)
    action = factory.LazyFunction(lambda: random.choice([i[0] for i in ACTION_CHOICES]))
    status = factory.LazyFunction(lambda: random.choice([i[0] for i in STATUS_CHOICES]))

    class Meta:
        model = IndustryProtocolS7Strategy


class FirewallBlackListFactory(BaseFactory):

    name = factory.Faker('text', max_nb_chars=80)
    publish_date = factory.Faker('past_datetime', tzinfo=timezone.get_default_timezone())
    action = factory.LazyFunction(lambda: random.choice([item[0] for item in FirewallBlackList.EVENT_PROCESS_CHOICES]))
    feature_code = factory.Faker('text', max_nb_chars=20)
    level = factory.LazyFunction(lambda: random.choice([item[0] for item in FirewallBlackList.LEVEL_CHOICE]))
    status = factory.LazyFunction(lambda: random.choice([0, 1]))


    class Meta:
        model = FirewallBlackList


class FirewallBlackListStrategyFactory(BaseStrategyFactory):
    name = factory.Faker('text', max_nb_chars=80)
    publish_date = factory.Faker('past_datetime', tzinfo=timezone.get_default_timezone())
    action = factory.LazyFunction(lambda: random.choice([item[0] for item in FirewallBlackListStrategy.EVENT_PROCESS_CHOICES]))
    feature_code = factory.Faker('text', max_nb_chars=20)
    level = factory.LazyFunction(lambda: random.choice([item[0] for item in FirewallBlackListStrategy.LEVEL_CHOICE]))
    status = factory.LazyFunction(lambda: random.choice([0, 1]))


    class Meta:
        model = FirewallBlackListStrategy


class FirewallIPMACBondStrategyFactory(BaseStrategyFactory):
    device_name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
    ip = factory.Faker('ipv4')
    mac = factory.Faker('mac_address')
    status = factory.LazyFunction(lambda: random.choice([i[0] for i in STATUS_CHOICES]))
    action = factory.LazyFunction(lambda: random.choice([i[0] for i in FirewallIPMACBondStrategy.ACTION_CHOICES]))

    class Meta:
        model = FirewallIPMACBondStrategy


class FirewallIPMACUnknownDeviceActionStrategyFactory(BaseStrategyFactory):
    action = factory.LazyFunction(
        lambda: random.choice([i[0] for i in FirewallIPMACUnknownDeviceActionStrategy.ACTION_CHOICES]))

    class Meta:
        model = FirewallIPMACUnknownDeviceActionStrategy


class FirewallSecEventFactory(TerminalLogFactory):
    src_ip = factory.Faker('ipv4')
    dst_ip = factory.Faker('ipv4')
    src_mac = factory.Faker('mac_address')
    dst_mac = factory.Faker('mac_address')
    protocol = factory.LazyFunction(lambda: random.choice(['tcp', 'udp']))
    app_layer_protocol = factory.LazyFunction(lambda: random.choice(['s7', 'modbus']))
    packet_length = factory.LazyFunction(lambda: random.randint(64, 1400))
    status = factory.LazyFunction(lambda: random.choice([i[0] for i in FirewallSecEvent.READ_STATUS_CHOICES]))
    level = factory.LazyFunction(lambda: random.choice([i[0] for i in FirewallSecEvent.LEVEL_CHOICES]))
    action = factory.LazyFunction(lambda: random.choice([i[0] for i in FirewallSecEvent.ACTION_CHOICES]))

    class Meta:
        model = FirewallSecEvent


class FirewallSysEventFactory(TerminalLogFactory):
    level = factory.LazyFunction(lambda: random.choice([i[0] for i in FirewallSysEvent.LEVEL_CHOICES]))
    type = factory.LazyFunction(lambda: random.choice([i[0] for i in FirewallSysEvent.EVENT_TYPE_CHOICES]))
    status = factory.LazyFunction(lambda: random.choice([i[0] for i in FirewallSysEvent.READ_STATUS_CHOICES]))

    class Meta:
        model = FirewallSysEvent
