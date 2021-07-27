import random

import factory
from django.utils import timezone
from faker import Faker
from factory import fuzzy

from base_app.models import Device, StrategyTemplate, REGISTER_CODE_LEN, \
    SECRET_LEN
from unified_log.models import LogProcessTemplate
from utils.base_tezt_data import BaseFactory
from utils.helper import random_string


fake = Faker()

# class DeviceFactory(BaseFactory):
#     name = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
#     type = factory.LazyFunction(lambda: random.choice([i[0] for i in Device.DEV_TEMP_TYPE_CHOICES]))
#     location = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
#     ip = factory.Faker('ipv4')
#     version = factory.Faker('text', locale='zh_CN', max_nb_chars=20)
#     responsible_user = factory.Faker('name', locale='zh_CN')
#     register_code = factory.LazyFunction(lambda: random_string(REGISTER_CODE_LEN))
#     # status = factory.LazyFunction(lambda: random.choice([i[0] for i in Device.STATUS_CHOICES]))
#     registered_time = factory.Faker('date_time', tzinfo=timezone.get_default_timezone())
#     audit_sec_alert_max_id = factory.LazyFunction(lambda: random.randint(1, 1000))
#     audit_sys_alert_max_id = factory.LazyFunction(lambda: random.randint(1, 1000))
#     audit_log_max_id = factory.LazyFunction(lambda: random.randint(1, 1000))
#     strategy_apply_status = factory.LazyFunction(
#         lambda: random.choice([i[0] for i in Device.STRATEGY_APPLY_STATUS_CHOICES]))
#     apply_time = factory.Faker('date_time', tzinfo=timezone.get_default_timezone())
#     secret = factory.LazyFunction(lambda: random_string(SECRET_LEN))
#     template_name = factory.Faker('text', locale='en_us', max_nb_chars=20)
#
#     class Meta:
#         model = Device

#
# 新的 Device 假数据
def _get_log_template():
    templates = LogProcessTemplate.objects.all()
    if not templates:
        return None
    else:
        return random.choice(templates)


class DeviceFactory(BaseFactory):
    name = factory.Sequence(lambda n: '资产 {}'.format(n))
    category = factory.LazyFunction(lambda: random.choice([i[0] for i in Device.CATEGORY_CHOICE]))
    type = factory.LazyFunction(lambda: random.choice([i[0] for i in Device.DEV_TEMP_TYPE_CHOICES]))
    location = factory.Faker('text', locale='zh_CN', max_nb_chars=10)
    ip = factory.Faker('ipv4')
    ip_mac_bond = random.choice([False, True])
    version = factory.Faker('text', locale='zh_CN', max_nb_chars=10)
    responsible_user = factory.Faker('name', locale='zh_CN')
    register_code = factory.LazyFunction(lambda: random_string(REGISTER_CODE_LEN))
    mac = factory.LazyFunction(lambda: fake.mac_address().upper())
    audit_sec_alert_max_id = factory.LazyFunction(lambda: random.randint(1, 1000))
    audit_sys_alert_max_id = factory.LazyFunction(lambda: random.randint(1, 1000))
    audit_log_max_id = factory.LazyFunction(lambda: random.randint(1, 1000))
    strategy_apply_status = factory.LazyFunction(
        lambda: random.choice([i[0] for i in Device.STRATEGY_APPLY_STATUS_CHOICES]))
    apply_time = factory.Faker('date_time', tzinfo=timezone.get_default_timezone())
    secret = factory.LazyFunction(lambda: random_string(SECRET_LEN))
    template_name = factory.Faker('text', locale='en_us', max_nb_chars=20)
    log_template = factory.LazyFunction(_get_log_template)
    log_status = True

    class Meta:
        model = Device

    @classmethod
    def create_normal(cls, *args, **kwargs):
        """
        测试的时候总是要默认把策略下发状态改为未下发，太麻烦了，所以这里单独一个方法生成
        方便使用的
        """
        kwargs['strategy_apply_status'] = 1
        return DeviceFactory.create(**kwargs)

    @classmethod
    def create_batch_normal(cls, *args, **kwargs):
        """
        测试的时候总是要默认把策略下发状态改为未下发，太麻烦了，所以这里单独一个方法生成
        方便使用的
        """
        kwargs['strategy_apply_status'] = 1
        return DeviceFactory.create_batch(*args, **kwargs)


class TemplateFactory(BaseFactory):
    name = factory.Faker('text', locale='zh_CN', max_nb_chars=32)
    type = factory.LazyFunction(lambda: random.choice([i[0] for i in Device.DEV_TEMP_TYPE_CHOICES]))
    created_time = factory.LazyFunction(lambda: timezone.now())

    class Meta:
        model = StrategyTemplate


class BaseStrategyFactory(BaseFactory):
    created_time = factory.LazyFunction(lambda: timezone.now())
    edit_time = factory.Faker('date_time', tzinfo=timezone.get_default_timezone())

    class Meta:
        abstract = True


class BaseLogFactory(BaseFactory):
    occurred_time = factory.LazyFunction(lambda: timezone.now())
    is_read = factory.Faker('pybool')
    read_at = factory.Faker('date_time', tzinfo=timezone.get_default_timezone())
    content = factory.Faker('text', max_nb_chars=1000)


class TerminalLogFactory(BaseLogFactory):
    device = factory.Iterator(Device.objects.all())
