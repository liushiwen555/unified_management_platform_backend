import random

import pytest
import factory
from django.utils import timezone
from factory import fuzzy

from base_app.factory_data import BaseLogFactory, DeviceFactory, BaseFactory
from log.models import UnifiedForumLog, DeviceAllAlert, ReportLog, SecurityEvent
from base_app.models import Device


class UnifiedForumLogFactory(BaseLogFactory):

    user = factory.Faker('first_name')
    ip = factory.Faker('ipv4')
    category = factory.LazyFunction(lambda: random.choice(
        [i[0] for i in UnifiedForumLog.CATEGORY_CHOICE]))
    type = factory.LazyFunction(lambda: random.choice(
        [i[0] for i in UnifiedForumLog.TYPE_CHOICE]))
    result = factory.Faker('pybool')

    class Meta:
        model = UnifiedForumLog


class DeviceAllAlertFactory(BaseLogFactory):

    name = factory.Faker('text', max_nb_chars=20)
    category = factory.LazyFunction(lambda: random.choice(
        [i[0] for i in DeviceAllAlert.EVENT_CATEGORY_CHOICE]))
    type = factory.LazyFunction(lambda: random.choice(
        [i[0] for i in DeviceAllAlert.TYPE_CHOICES]))
    level = factory.LazyFunction(lambda: random.choice(
        [i[0] for i in DeviceAllAlert.LEVEL_CHOICE]))
    desc = factory.Faker('text', max_nb_chars=70)
    log_desc = factory.Faker('text', max_nb_chars=70)
    sec_desc = factory.Faker('text', max_nb_chars=70)
    example_desc = factory.Faker('text', max_nb_chars=70)
    suggest_desc = factory.Faker('text', max_nb_chars=70)
    src_ip = factory.Faker('ipv4')
    dst_ip = factory.Faker('ipv4')
    src_mac = factory.Faker('mac_address')
    dst_mac = factory.Faker('mac_address')
    src_port = factory.LazyFunction(lambda: random.randint(1, 65535))
    dst_port = factory.LazyFunction(lambda: random.randint(1, 65535))
    first_at = factory.Faker('date_time', tzinfo=timezone.get_default_timezone())
    last_at = factory.Faker('date_time', tzinfo=timezone.get_default_timezone())
    device = factory.LazyFunction(lambda: random.choice(Device.objects.all()))
    src_country = factory.Faker('country')
    src_province = factory.Faker('text', max_nb_chars=5)
    src_city = factory.Faker('city')
    src_private = factory.LazyFunction(lambda: random.choice([False, True]))
    dst_country = factory.Faker('country')
    dst_province = factory.Faker('text', max_nb_chars=5)
    dst_city = factory.Faker('city')
    dst_private = factory.LazyFunction(lambda: random.choice([False, True]))

    class Meta:
        model = DeviceAllAlert


class ReportLogFactory(BaseFactory):
    start_time = factory.Faker('date_time_this_month',
                               tzinfo=timezone.get_default_timezone())
    end_time = factory.Faker('date_time_this_month',
                             tzinfo=timezone.get_default_timezone())
    alert_count = factory.LazyFunction(lambda: random.randint(1, 1000))
    auditor_alert_count = factory.LazyFunction(lambda: random.randint(1, 1000))
    firewall_alert_count = factory.LazyFunction(lambda: random.randint(1, 1000))
    sys_alert_count = factory.LazyFunction(lambda: random.randint(1, 1000))
    device_alert_count = factory.LazyFunction(lambda: random.randint(1, 1000))

    alert_per = factory.LazyFunction(lambda: random.randint(1, 100))
    auditor_alert_per = factory.LazyFunction(lambda: random.randint(1, 100))
    firewall_alert_per = factory.LazyFunction(lambda: random.randint(1, 100))
    sys_alert_per = factory.LazyFunction(lambda: random.randint(1, 100))
    device_alert_per = factory.LazyFunction(lambda: random.randint(1, 100))

    sec_device_add = factory.LazyFunction(lambda: random.randint(10, 100))
    com_device_add = factory.LazyFunction(lambda: random.randint(10, 100))
    ser_device_add = factory.LazyFunction(lambda: random.randint(10, 100))
    con_device_add = factory.LazyFunction(lambda: random.randint(10, 100))

    unified_log_count = factory.LazyFunction(lambda: random.randint(10, 10000))
    auditor_log_count = factory.LazyFunction(lambda: random.randint(10, 10000))
    firewall_log_count = factory.LazyFunction(lambda: random.randint(10, 10000))
    login_account_count = factory.LazyFunction(lambda: random.randint(10, 10000))

    class Meta:
        model = ReportLog


class SecurityEventFactory(BaseFactory):
    device = factory.LazyFunction(lambda: random.choice(Device.objects.all()))
    category = fuzzy.FuzzyChoice([i[0] for i in SecurityEvent.CATEGORY_CHOICES])
    type = fuzzy.FuzzyChoice([i[0] for i in SecurityEvent.TYPE_CHOICES])
    level = fuzzy.FuzzyChoice([i[0] for i in SecurityEvent.LEVEL_CHOICE])
    content = factory.Faker('text', max_nb_chars=100)
    status_resolved = fuzzy.FuzzyChoice([i[0] for i in SecurityEvent.RESOLVED_STATUS_CHOICES])

    class Meta:
        model = SecurityEvent
