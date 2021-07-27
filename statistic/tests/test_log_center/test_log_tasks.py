import time
from datetime import timedelta
from typing import Dict

import pytest
from django.utils import timezone

from base_app.factory_data import DeviceFactory
from log.factory_data import UnifiedForumLogFactory
from statistic.tasks import LogStatisticDayTask, LogStatisticTask, \
    LogDstIPTopFiveTask, LogCategoryDistributionTask, LogPortDistributionTask, \
    DeviceLogCountTask
from unified_log.elastic.elastic_client import client
from unified_log.models import LogStatistic
from log.models import UnifiedForumLog


def collect_logs(target, data: Dict):
    current = timezone.now()
    for key, value in data.items():
        for _ in range(value):
            data = {'timestamp': current, target: key}
            client.save(
                index_name='test-log-statistic-task',
                data=data,
            )
    client.flush_index('test-log-statistic-task')
    time.sleep(1)
    

@pytest.mark.django_db
class TestLogStatistic:
    @pytest.fixture(scope='function')
    def clean(self):
        client.delete_index('test-*')

    @pytest.fixture(scope='class')
    def datetime_data(self):
        data = {}
        d = timezone.now() - timedelta(days=1)
        for i in range(10):
            data[d - timedelta(days=i)] = (i + 1) * 2
        return data

    @pytest.fixture(scope='function')
    def unified_log(self):
        current = timezone.now()
        return UnifiedForumLogFactory.create_batch(20, occurred_time=current)

    def test_log_statistic_task(self, unified_log):
        """
        测试本机累计日志，采集累计日志，今日本地日志，今日采集日志，每小时采集日志量
        """
        client.delete_index('test-*')
        current = timezone.now()
        last_hour = current - timedelta(minutes=50)
        last = current - timedelta(days=1)
        collect_logs('timestamp', {current: 20, last_hour: 10, last: 30})
        data = LogStatisticTask.run(timezone.now())
        assert data.local == 40
        assert data.collect == 60
        assert data.local_current == 40
        assert data.collect_current == 30
        assert data.local_hour == 40
        assert data.collect_hour == 30

    def test_get_local(self):
        data = LogStatisticTask.run(timezone.now())
        UnifiedForumLog.objects.filter().delete()
        data1 = LogStatisticTask.run(timezone.now())

        assert data.local == data1.local
        UnifiedForumLogFactory.create_batch(20)
        data2 = LogStatisticTask.run(timezone.now())
        assert data2.local == data1.local + 20

    def test_get_collect(self):
        current = timezone.now()
        collect_logs('timestamp', {current: 20})
        current1 = timezone.now()
        data = LogStatisticTask.run(current1)
        collect_logs('timestamp', {current1: 20})
        data1 = LogStatisticTask.run(timezone.now())
        assert data1.collect == data.collect + 20

    def test_log_statistic_day_task(self, clean, datetime_data):
        """
        测试每日本地日志量和采集日志量
        """
        collect_logs('timestamp', datetime_data)
        current = timezone.now()
        cnt = 0
        for key, value in datetime_data.items():
            UnifiedForumLogFactory.create_batch(value, occurred_time=key)
            date = (current - timedelta(days=cnt)).replace(minute=0,
                                                           microsecond=0)
            data = LogStatisticDayTask.run(date)
            assert data.local_today == value
            assert data.collect_today == value
            cnt += 1


@pytest.mark.django_db
class TestLogDstIPTopFiveTask:
    """
    测试今日目的IP TOP5
    """
    @pytest.fixture(scope='class')
    def dst_ips(self):
        data = {
            '127.1.1.1': 20,
            '200.200.200.200': 15,
            '192.155.11.11': 12,
            '200.200.200.222': 10,
            '200.200.200.33': 9,
            '123.123.123.123': 8,
        }
        return data

    def test_dst_ip_top_five_task(self, dst_ips):
        collect_logs('dst_ip', dst_ips)
        data = LogDstIPTopFiveTask.run(timezone.now())

        assert data.ip == list(dst_ips.keys())[:5]
        assert data.today == list(dst_ips.values())[:5]


@pytest.mark.django_db
class TestLogCategoryDistributionTask:
    """
    测试今日四种资产类型日志分布
    """
    @pytest.fixture(scope='class')
    def categories(self):
        data = {
            '安全资产': 5,
            '网络资产': 10,
            '主机资产': 15,
            '工控资产': 20,
        }
        return data

    def test_log_statistic_category_distribution(self, categories):

        collect_logs('dev_category', categories)
        data = LogCategoryDistributionTask.run(timezone.now())

        assert data.security == 5
        assert data.network == 10
        assert data.server == 15
        assert data.control == 20


@pytest.mark.django_db
class TestLogPortDistributionTask:
    """
    测试今日端口分布
    """
    @pytest.fixture(scope='class')
    def ports(self):
        data = {}
        for i in range(10, 21):
            data[i] = i * 2
        return data

    def test_log_port_distribution_task(self, ports: Dict[str, int]):
        collect_logs('dst_port', ports)
        collect_logs('dst_port', {300: 1, 2000: 2, 400: 3})
        data = LogPortDistributionTask.run(timezone.now())

        port_keys = list(ports.keys())[::-1][:10]
        port_keys.append('其他')
        port_values = list(ports.values())[::-1][:10]
        port_values.append(26)
        assert data.ports == port_keys
        assert data.total == port_values


@pytest.mark.django_db
class TestDeviceLogCountTask:
    """
    测试今日资产日志每小时统计一次总量
    """
    @pytest.fixture(scope='class')
    def dev_ids(self):
        devices = DeviceFactory.create_batch_normal(6)
        data = {d.id: d.id + 10 for d in devices}
        return data

    def test_device_log_count(self, dev_ids):
        collect_logs('dev_id', dev_ids)
        DeviceLogCountTask.run(timezone.now())

        ids = list(dev_ids.keys())
        log0 = LogStatistic.objects.get(device__id=ids[0])
        assert log0.total == ids[0] + 10
        assert log0.today == ids[0] + 10

