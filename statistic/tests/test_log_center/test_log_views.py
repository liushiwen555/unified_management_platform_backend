from datetime import timedelta

import pytest
from django.utils import timezone
from django.urls import reverse
from rest_framework.test import APIClient

from utils.base_testcase import BaseViewTest
from statistic.factory_data import LogStatisticFactory, LogStatisticDayFactory, LogCategoryDistributionFactory
from statistic.models import LogDstIPTopFive, LogPortDistribution
from unified_log.factory_data import LogStatisticFactory as DeviceLogFactory
from unified_log.models import LogStatistic as DeviceLog
from base_app.models import Device


@pytest.mark.django_db
class TestLogStatisticView(BaseViewTest):
    """
    日志中心——日志总量，本地累计日志，采集日志，今日新增
    """
    def test_log_statistic(self, config_client: APIClient):
        log = LogStatisticFactory.create(update_time=timezone.now())
        response = config_client.get(reverse('log-total')).json()

        assert response['total'] == log.total
        assert response['local'] == log.local
        assert response['collect'] == log.collect
        assert response['increase'] == log.collect_current + log.local_current


@pytest.mark.django_db
class TestLogStatisticDayView(BaseViewTest):
    """
    日志中心——近15天的本地日志量
    15天的每天的采集量+今天的采集量
    """
    def test_log_statistic_day(self, config_client: APIClient):
        local = []
        current = timezone.now()
        for i in range(15):
            log = LogStatisticDayFactory.create(
                update_time=current - timedelta(days=i))
            local.append(log.local_today)
        c = LogStatisticFactory.create(update_time=timezone.now())
        response = config_client.get(reverse('log-day-trend')).json()

        assert response['local']['data'] == local[::-1]
        assert response['local_today'] == c.local_current


@pytest.mark.django_db
class TestLogStatisticHourView(BaseViewTest):
    """
    日志中心采集趋势
    """
    def test_log_statistic_hour(self, config_client: APIClient):
        collect = []
        for i in range(24):
            data = LogStatisticFactory.create(update_time=timezone.now())
            collect.append(data.collect_hour)

        response = config_client.get(reverse('log-hour-trend')).json()
        assert response['collect']['data'] == collect


@pytest.mark.django_db
class TestDeviceTopFive(BaseViewTest):
    """
    日志中心——今日资产日志TOP5
    """
    def test_device_top_five(self, config_client: APIClient):
        devices = Device.objects.all()[:10]
        for d in devices:
            DeviceLogFactory.create(device=d)

        response = config_client.get(reverse('log-device-top-five')).json()
        devices = DeviceLog.objects.values_list(
            'device__name', flat=True).order_by('-today')[:5]

        assert [d['device_name'] for d in response['data']] == list(devices)


@pytest.mark.django_db
class TestDstIPTopFive(BaseViewTest):
    """
    日志中心——今日目的IP TOP5
    """
    def test_dst_ip_top_five(self, config_client: APIClient):
        log = LogDstIPTopFive.objects.create(
            ip=['127.1.1.1', '127.1.1.2', '127.1.1.3'],
            today=[100, 80, 60],
            update_time=timezone.now()
        )
        response = config_client.get(reverse('log-dst-ip-top-five')).json()

        target = [
            {'ip': '127.1.1.1', 'percent': 100, 'today': 100},
            {'ip': '127.1.1.2', 'percent': 80, 'today': 80},
            {'ip': '127.1.1.3', 'percent': 60, 'today': 60},
        ]
        assert response['data'] == target

    def test_none_data(self, config_client: APIClient):
        response = config_client.get(reverse('log-dst-ip-top-five')).json()
        assert response['data'] == []

    def test_zero_data(self, config_client: APIClient):
        log = LogDstIPTopFive.objects.create(
            ip=['127.1.1.1', '127.1.1.2', '127.1.1.3'],
            today=[0, 0, 0],
            update_time=timezone.now()
        )
        response = config_client.get(reverse('log-dst-ip-top-five')).json()
        target = [
            {'ip': '127.1.1.1', 'percent': 0, 'today': 0},
            {'ip': '127.1.1.2', 'percent': 0, 'today': 0},
            {'ip': '127.1.1.3', 'percent': 0, 'today': 0},
        ]
        assert response['data'] == target


@pytest.mark.django_db
class TestCategoryDistribution(BaseViewTest):
    def test_category_distribution(self, config_client: APIClient):
        log = LogCategoryDistributionFactory.create()

        response = config_client.get(reverse('log-category-distribution')).json()

        assert response['security'] == log.security
        assert response['server'] == log.server
        assert response['network'] == log.network
        assert response['control'] == log.control


@pytest.mark.django_db
class TestLogPortDistributionView(BaseViewTest):
    def test_port_distribution(self, config_client: APIClient):
        ports = ['161', '514', '1234', '其他']
        total = [100, 200, 300, 400]
        LogPortDistribution.objects.create(
            ports=ports, total=total, update_time=timezone.now())

        response = config_client.get(reverse('log-port-distribution')).json()

        assert response['ports'] == ports
        assert response['total'] == total
