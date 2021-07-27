from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from auditor.bolean_auditor.process_protocol import IPSource
from auditor.factory_data import AttackIPStatisticFactory
from base_app.factory_data import DeviceFactory
from base_app.models import Device
from log.factory_data import DeviceAllAlertFactory, SecurityEventFactory
from log.models import DeviceAllAlert, SecurityEvent
from statistic.factory_data import MainViewFactory, LogCenterFactory
from utils.base_testcase import BaseViewTest
from utils.helper import safe_divide


@pytest.mark.django_db
class TestMainView(BaseViewTest):
    def test_assets_center(self, config_client: APIClient):
        """
        运营态势主视图资产中心
        """
        DeviceFactory.create_batch_normal(20)
        DeviceFactory.create_batch_normal(5, category=None, type=None)

        response = config_client.get(reverse('assets-center'))
        response = response.json()

        assert response['all'] == Device.objects.all().count()
        assert response['security'] == Device.objects.filter(
            category=Device.CATEGORY_Security).count()
        assert response['server'] == Device.objects.filter(
            category=Device.CATEGORY_Sever).count()
        assert response['network'] == Device.objects.filter(
            category=Device.CATEGORY_Communication).count()
        assert response['control'] == Device.objects.filter(
            category=Device.CATEGORY_Control).count()

    def test_monitor_center(self, config_client: APIClient):
        """
        性能中心   在线率指的是在线资产占所有资产的百分比
        """
        DeviceFactory.create_batch_normal(20)
        DeviceFactory.create_batch_normal(10, monitor=True)

        response = config_client.get(reverse('monitor-center')).json()

        total = Device.objects.count()
        assert response['monitor_count'] == Device.objects.filter(
            monitor=True).count()
        assert response['monitor_percent'] == safe_divide(
            response['monitor_count'] * 100, total)
        assert response['online_percent'] == safe_divide(
            Device.objects.filter(status=Device.ONLINE).count() * 100, total)

    def test_main_view(self, config_client: APIClient):
        """
        主视图中间的数据
        """
        source = IPSource(timezone.now())
        source.clean()
        source._attack_data['external_ip'] = 10
        source.save_attack_data()

        main_view = MainViewFactory.create()
        ip_statistic = AttackIPStatisticFactory.create()

        response = config_client.get(reverse('main-view')).json()

        # 外网IP，是通过协议审计同步过来的累计数据+今日分析出来的数据
        assert response['ip_count'] == ip_statistic.external_ip + \
               source.get_attack_data()['external_ip']
        assert response['alert_count'] == main_view.alert_count
        assert response['un_resolved'] == main_view.un_resolved
        assert response['log_count'] == main_view.log_count

    def test_alert_process(self, config_client: APIClient):
        """
        运营态势——待处理安全告警统计
        """
        DeviceAllAlertFactory.create_batch(20)
        SecurityEventFactory.create_batch(20)

        total = DeviceAllAlert.objects.count() + SecurityEvent.objects.count()
        un_total = DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count() + \
                   SecurityEvent.objects.filter(
                       status_resolved=SecurityEvent.STATUS_UNRESOLVED).count()
        high = DeviceAllAlert.objects.filter(
            level=DeviceAllAlert.LEVEL_HIGH).count() + \
               SecurityEvent.objects.filter(
                   level=SecurityEvent.LEVEL_HIGH).count()
        un_high = DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED,
            level=DeviceAllAlert.LEVEL_HIGH).count() + \
                  SecurityEvent.objects.filter(
                      status_resolved=SecurityEvent.STATUS_UNRESOLVED,
                      level=SecurityEvent.LEVEL_HIGH).count()

        response = config_client.get(reverse('alert-process')).json()

        assert response['percent'] == safe_divide(un_total * 100, total)
        assert response['high_percent'] == safe_divide(un_high * 100, high)

    def test_log_center(self, config_client: APIClient):
        """
        运营态势主视图——日志中心
        """
        current = timezone.now()
        collect = []
        parsed = []
        for i in range(10):
            d = LogCenterFactory.create(update_time=current-timedelta(minutes=10))
            collect.append(d.collect)
            parsed.append(d.parsed)

        response = config_client.get(reverse('log-center')).json()
        assert response['collect'] == {'data': collect[::-1]}
        assert response['parsed'] == {'data': parsed[::-1]}
