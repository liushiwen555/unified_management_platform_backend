import pytest
from django.utils import timezone
from faker import Faker

from auditor.models import AuditSysAlert, AuditSecAlert
from base_app.factory_data import DeviceFactory
from base_app.models import Device
from firewall.models import FirewallSysEvent, FirewallSecEvent
from log.models import DeviceAllAlert, UnifiedForumLog, SecurityEvent
from statistic.tasks import MainViewTask, AssetsCenterTask, \
    MonitorCenterTask, LogStatisticDayTask, LogStatisticTask, \
    LogDstIPTopFiveTask, DeviceLogCountTask
from unified_log.elastic.elastic_client import client
from unified_log.elastic.elastic_model import BaseDocument

fake = Faker()


@pytest.mark.django_db
class TestTasks:
    def test_main_view(self):
        main_view = MainViewTask.run(timezone.now())
        print(main_view)

        unified_count = 0
        for model in [UnifiedForumLog, FirewallSecEvent, FirewallSysEvent,
                      AuditSysAlert, AuditSecAlert]:
            unified_count += model.objects.count()
        assert main_view.log_count == \
               BaseDocument.search().count() + unified_count
        assert main_view.alert_count == DeviceAllAlert.objects.count() + SecurityEvent.objects.count()
        assert main_view.un_resolved == DeviceAllAlert.objects.filter(
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).count() + \
               SecurityEvent.objects.filter(status_resolved=SecurityEvent.STATUS_UNRESOLVED).count()

    def test_assets_task(self):
        result = AssetsCenterTask.run(timezone.now())
        assert result.security == Device.objects.filter(
            category=Device.CATEGORY_Security).count()
        assert result.server == Device.objects.filter(
            category=Device.CATEGORY_Sever).count()
        assert result.control == Device.objects.filter(
            category=Device.CATEGORY_Control).count()
        assert result.network == Device.objects.filter(
            category=Device.CATEGORY_Communication).count()

    def test_monitor_task(self):
        DeviceFactory.create_batch_normal(20)
        DeviceFactory.create_batch_normal(10, monitor=True)
        result = MonitorCenterTask.run(timezone.now())
        assert result.monitor_count == Device.objects.filter(
            monitor=True).count()
        assert result.online_percent == round(
            Device.objects.filter(
                status=Device.ONLINE).count() / result.monitor_count * 100)

    def test_log_statistic_task(self):
        LogStatisticTask.run(timezone.now())

    def test_log_statistic_day_task(self):
        LogStatisticDayTask.run(timezone.now())

    def test_log_dst_ip_top_five(self):
        data = {'timestamp': timezone.now(), 'dst_ip': '192.168.1.1'}
        client.save(
            index_name='test-log-statistic-task',
            data=data,
        )
        LogDstIPTopFiveTask.run(timezone.now())

    def test_device_log_count_task(self):
        DeviceLogCountTask.run(timezone.now())
