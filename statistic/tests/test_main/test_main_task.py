"""
运营态势主视图单元测试
"""
from datetime import datetime, timedelta

import pytest
from django.utils import timezone

from statistic.tasks import MainViewTask, AssetsCenterTask, MonitorCenterTask, LogCenterTask
from statistic.models import MainView
from base_app.factory_data import DeviceFactory
from base_app.models import Device
from log.models import SecurityEvent, DeviceAllAlert, UnifiedForumLog
from auditor.models import AuditSecAlert, AuditSysAlert
from unified_log.elastic.elastic_model import BaseDocument
from unified_log.factory_data import BaseLogFactory


@pytest.fixture(scope='class')
def current() -> datetime:
    current_ = datetime(2020, 12, 20, 2, 0, 0).astimezone(timezone.utc)
    return current_


@pytest.mark.django_db
class TestMainViewTask:
    """
    测试运营态势中间大屏
    """

    def test_alert_count(self):
        """
        全部告警=安全威胁+安全事件
        """
        count = MainViewTask.alert_count()
        assert count == DeviceAllAlert.objects.count() + \
               SecurityEvent.objects.count()

    def test_un_resolved(self):
        """
        待处理告警=待处理安全事件+待处理安全威胁
        """
        count = MainViewTask.un_resolved()
        assert count == DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count() + SecurityEvent.objects.filter(
            status_resolved=SecurityEvent.STATUS_UNRESOLVED).count()

    def test_log_count(self):
        """
        包含采集日志，本机日志，防火墙审计同步日志
        :return:
        """
        count = MainViewTask.log_count()
        target = BaseDocument.search().count() + UnifiedForumLog.objects.count() \
                 + AuditSecAlert.objects.count() + AuditSysAlert.objects.count()

        assert count == target

    def test_run(self, current: datetime):
        data = MainViewTask.run(current)
        assert data.update_time == current
        assert data.alert_count == DeviceAllAlert.objects.count() + SecurityEvent.objects.count()


@pytest.mark.django_db
class TestAssetsCenter:
    def test_run(self, current: datetime):
        for cate, _ in Device.CATEGORY_CHOICE:
            DeviceFactory.create_batch_normal(cate * 5, category=cate)
        data = AssetsCenterTask.run(current)

        assert data.security == Device.objects.filter(
            category=Device.CATEGORY_Security).count()
        assert data.server == Device.objects.filter(
            category=Device.CATEGORY_Sever).count()
        assert data.control == Device.objects.filter(
            category=Device.CATEGORY_Control).count()
        assert data.network == Device.objects.filter(
            category=Device.CATEGORY_Communication).count()
        assert data.update_time == current


@pytest.mark.django_db
class TestMonitorCenterTask:
    def test_run(self, current: datetime):
        """
        开启了性能监控的资产统计
        监控资产：当前开启了性能监控的资产总数
        启用比率：截止当前性能监控为启用的占全部资产的比例
        在线率：当前在线的资产占所有资产
        """
        DeviceFactory.create_batch_normal(10, monitor=True)
        DeviceFactory.create_batch_normal(10, monitor=True, status=Device.ONLINE)

        online = Device.objects.filter(status=Device.ONLINE).count()
        total = Device.objects.count()
        monitor = Device.objects.filter(monitor=True).count()

        data = MonitorCenterTask.run(current)
        assert data.monitor_count == monitor
        assert data.monitor_percent == round(monitor * 100 / total)
        assert data.online_percent == round(online * 100 / total)


@pytest.mark.django_db
class TestLogCenterTask:
    def test_run(self, current: datetime):
        BaseLogFactory.create_batch(20, timestamp=current)
        BaseLogFactory.create_batch(20, timestamp=current, status=True)

        data = LogCenterTask.run(current)
        last = current - timedelta(minutes=10)
        assert data.collect == BaseDocument.search().filter(
            'range', timestamp={'gte': last, 'lte': current}).count()
        assert data.collect == BaseDocument.search().filter(
            'range', timestamp={'gte': last, 'lte': current}).filter(
            'term', status=True).count()
