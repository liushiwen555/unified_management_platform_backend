import random

import factory
from faker import Faker

from setting.models import Setting
from utils.base_tezt_data import BaseFactory

fake = Faker('zh_CN')


class SettingFactory(BaseFactory):
    lockout_threshold = factory.LazyFunction(lambda: random.randint(1, 10))
    lockout_duration = factory.LazyFunction(lambda: random.randint(1, 60))
    reset_lockout_counter_after = factory.LazyFunction(lambda: random.randint(1, 30))
    login_timeout_duration = factory.LazyFunction(lambda: random.randint(1, 30))
    ip_limit_enable = factory.Faker('pybool')
    # generate a list of ipv4 address whose length is between 1 and 9.
    allowed_ip = factory.LazyFunction(
        lambda: [factory.Faker('ipv4').generate({}) for _ in range(random.randrange(1, 10))])

    class Meta:
        model = Setting


def ip_info_factory():
    keys = ['address', 'net_mask', 'gateway']
    r = {}
    for k in keys:
        d = {k: fake.ipv4_private()}
        r.update(d)
    return r


def time_info_factory():
    r = dict(
        time=fake.date_time(),
    )
    return r