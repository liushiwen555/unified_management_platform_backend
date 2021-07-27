import factory
from django.utils import timezone
from factory import fuzzy

from statistic.models import MainView, AssetsCenter, MonitorCenter, LogCenter, \
    SystemRunning, LogStatisticDay, LogStatistic, LogCategoryDistribution
from utils.base_tezt_data import BaseFactory
from utils.constants import NETWORK_STATUS


class MainViewFactory(BaseFactory):
    alert_count = fuzzy.FuzzyInteger(10, 200)
    un_resolved = fuzzy.FuzzyInteger(10, 50)
    log_count = fuzzy.FuzzyInteger(100, 3000)
    update_time = factory.Faker('date_time', tzinfo=timezone.utc)

    class Meta:
        model = MainView


class AssetsCenterFactory(BaseFactory):
    all = fuzzy.FuzzyInteger(100, 200)
    security = fuzzy.FuzzyInteger(10, 50)
    server = fuzzy.FuzzyInteger(10, 50)
    network = fuzzy.FuzzyInteger(10, 50)
    control = fuzzy.FuzzyInteger(10, 50)
    update_time = factory.Faker('date_time', tzinfo=timezone.utc)

    class Meta:
        model = AssetsCenter


class MonitorCenterFactory(BaseFactory):
    monitor_count = fuzzy.FuzzyInteger(100, 200)
    monitor_percent = fuzzy.FuzzyInteger(1, 100)
    online_percent = fuzzy.FuzzyInteger(1, 100)
    update_time = factory.Faker('date_time', tzinfo=timezone.utc)

    class Meta:
        model = MonitorCenter


class LogCenterFactory(BaseFactory):
    collect = fuzzy.FuzzyInteger(1000, 3000)
    parsed = fuzzy.FuzzyInteger(1000, 3000)
    update_time = factory.Faker('date_time', tzinfo=timezone.utc)

    class Meta:
        model = LogCenter


class SystemRunningFactory(BaseFactory):
    cpu = fuzzy.FuzzyInteger(0, 100)
    memory = fuzzy.FuzzyInteger(0, 100)
    disk = fuzzy.FuzzyInteger(0, 100)
    network = [
        {'name': 'MGMT', 'speed': 0, 'status': NETWORK_STATUS[
            'link beat detected']}
    ]

    class Meta:
        model = SystemRunning


class LogStatisticDayFactory(BaseFactory):
    """
    日志中心按天统计日志
    """
    local_today = fuzzy.FuzzyInteger(0, 100)
    collect_today = fuzzy.FuzzyInteger(0, 100)

    class Meta:
        model = LogStatisticDay


class LogStatisticFactory(BaseFactory):
    """
    日志中心每小时统计
    """
    total = fuzzy.FuzzyInteger(100, 2000)
    local = fuzzy.FuzzyInteger(100, 2000)
    collect = fuzzy.FuzzyInteger(100, 2000)
    local_current = fuzzy.FuzzyInteger(100, 2000)
    collect_current = fuzzy.FuzzyInteger(100, 2000)
    local_hour = fuzzy.FuzzyInteger(100, 2000)
    collect_hour = fuzzy.FuzzyInteger(100, 2000)

    class Meta:
        model = LogStatistic


class LogCategoryDistributionFactory(BaseFactory):
    security = fuzzy.FuzzyInteger(100, 2000)
    server = fuzzy.FuzzyInteger(100, 2000)
    network = fuzzy.FuzzyInteger(100, 2000)
    control = fuzzy.FuzzyInteger(100, 2000)
    update_time = factory.Faker('date_time', tzinfo=timezone.utc)

    class Meta:
        model = LogCategoryDistribution


