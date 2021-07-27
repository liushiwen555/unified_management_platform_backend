import random
import time

import factory
from django.utils import timezone
from factory import fuzzy
from faker import Faker

from base_app.factory_data import BaseFactory
from base_app.models import Device
from unified_log.elastic.elastic_model import AuthLog, BaseDocument
from unified_log.models import LOG_TYPE_CHOICES, ADD_TYPE_CHOICES, \
    LogProcessRule, LogProcessTemplate, LogStatistic
from utils.constants import DEV_TEMP_TYPE_CHOICES, CATEGORY_CHOICE

AUTH_RULE = (r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
             r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
             r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
             r'(.*?(from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
             r'port (?P<src_port>\d+)).*?|.*?)')

fake = Faker()


class LogProcessRuleFactory(BaseFactory):
    name = factory.Sequence(lambda n: 'LogRule{}'.format(n))
    category = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.CATEGORY_CHOICES)[0])
    type = factory.LazyFunction(lambda: random.choice(
        LogProcessRule.TYPE_CHOICES)[0])
    brand = factory.Faker('text', max_nb_chars=10)
    hardware = factory.Faker('text', max_nb_chars=10)
    add = factory.LazyFunction(lambda: random.choice(ADD_TYPE_CHOICES)[0])
    update_time = factory.Faker('date_time')
    pattern = factory.Faker('text')
    example = factory.Faker('text')
    log_type = factory.LazyFunction(lambda: random.choice(LOG_TYPE_CHOICES)[0])
    mark = factory.Faker('text', max_nb_chars=20)

    class Meta:
        model = LogProcessRule


class LogProcessTemplateFactory(BaseFactory):
    name = factory.Sequence(lambda n: 'LogT{}'.format(n))
    category = factory.LazyFunction(lambda: random.choice(CATEGORY_CHOICE)[0])
    type = factory.LazyFunction(lambda: random.choice(DEV_TEMP_TYPE_CHOICES)[0])
    brand = factory.Faker('text', max_nb_chars=10)
    hardware = factory.Faker('text', max_nb_chars=10)
    add = factory.LazyFunction(lambda: random.choice(ADD_TYPE_CHOICES)[0])
    update_time = factory.Faker('date_time')
    mark = factory.Faker('text', max_nb_chars=20)

    kern = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    user = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    mail = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    daemon = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    auth = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    syslog = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    lpr = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    cron = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    ftp = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    authpriv = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    local0 = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    local1 = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    local2 = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    local3 = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    local4 = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    local5 = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    local6 = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))
    local7 = factory.LazyFunction(
        lambda: random.choice(LogProcessRule.objects.all()))

    class Meta:
        model = LogProcessTemplate


class BaseLogFactory():
    ip = factory.Faker('ipv4')
    src_ip = factory.Faker('ipv4')
    src_port = factory.LazyFunction(lambda: random.randint(1, 65536))
    dst_ip = factory.Faker('ipv4')
    dst_port = factory.LazyFunction(lambda: random.randint(1, 65536))
    dev_name = factory.Faker('text', max_nb_chars=10)
    dev_type = factory.LazyFunction(
        lambda: random.choice(DEV_TEMP_TYPE_CHOICES)[1])
    dev_category = factory.LazyFunction(
        lambda: random.choice(CATEGORY_CHOICE)[1])
    log_time = factory.Faker('date_time')
    timestamp = factory.Faker('date_time')
    content = factory.Faker('text')
    id = factory.Sequence(lambda n: n)
    dev_id = fuzzy.FuzzyInteger(1, 100)

    @classmethod
    def create(cls, **kwargs):
        data = dict(
            ip=fake.ipv4(),
            src_ip=fake.ipv4(),
            src_port=random.randint(1, 500),
            dev_name=fake.text(max_nb_chars=20),
            dev_type=random.choice(DEV_TEMP_TYPE_CHOICES)[1],
            dev_category=random.choice(CATEGORY_CHOICE)[1],
            dst_ip=fake.ipv4(),
            dst_port=random.randint(1, 500),
            log_time=fake.date_time(),
            content=fake.text(),
            dev_id=random.randint(1, 10),
        )

        for key, d in kwargs.items():
            data[key] = d
        log = BaseDocument(**data)
        log.save()

    @classmethod
    def create_batch(cls, size, **kwargs):
        for i in range(size):
            cls.create(**kwargs)
        time.sleep(1)


class AuthLogFactory(BaseLogFactory):
    class Meta:
        model = AuthLog


class LogStatisticFactory(BaseFactory):
    device = fuzzy.FuzzyChoice(Device.objects.all())
    today = fuzzy.FuzzyInteger(100, 1000)
    total = fuzzy.FuzzyInteger(100, 1000)
    update_time = factory.Faker('date_time', tzinfo=timezone.utc)

    class Meta:
        model = LogStatistic
