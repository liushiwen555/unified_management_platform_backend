from datetime import timedelta
from typing import Dict

from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode
from rest_framework.test import APIClient

from auditor.factory_data import AuditSysAlertFactory
from auditor.models import AuditSysAlert
from base_app.factory_data import DeviceFactory
from firewall.factory_data import FirewallSysEventFactory
from firewall.models import FirewallSysEvent
from log.models import DeviceAllAlert, SecurityEvent
from log.factory_data import ReportLogFactory, DeviceAllAlertFactory, SecurityEventFactory
from utils.base_testcase import BaseViewTest, SecurityEngineerPermission


class TestPermissions(BaseViewTest):
    @SecurityEngineerPermission.permission_read
    def test_read_permissions(self, all_client: Dict[str, APIClient], user: str,
                              expect_code: int):
        report = ReportLogFactory.create()
        client = all_client[user]
        target = ['download-report-log']
        args = [report.id]

        for i in range(len(target)):
            url = reverse(target[i], args=(args[i],))
            response = client.get(url)

            assert response.status_code == expect_code


class TestAuditLogSearch(BaseViewTest):
    def test_search_audit_log(self, config_client: APIClient):
        current = timezone.now()
        device = DeviceFactory.create_normal()
        AuditSysAlertFactory.create(
            device=device, ip=device.ip, is_read=False,
            category=AuditSysAlert.CATEGORY_ALERT_CPU,
            occurred_time=current
        )

        response = config_client.get(
            reverse('auditor-log-list'),
            data=dict(
                dev_name=device.name,
                is_read=False,
                ip=device.ip,
                category=AuditSysAlert.CATEGORY_ALERT_CPU,
                start_time=str(current - timedelta(hours=1)),
                end_time=str(current + timedelta(hours=1)),
            )
        )

        assert response.data['count'] == 1


class TestFirewallLogSearch(BaseViewTest):
    def test_search_firewall_log(self, config_client):
        current = timezone.now()
        device = DeviceFactory.create_normal()
        FirewallSysEventFactory.create(
            device=device, is_read=False, level=FirewallSysEvent.LEVEL_MESSAGE,
            occurred_time=current
        )

        response = config_client.get(
            reverse('firewall-log-list'),
            data=dict(
                dev_name=device.name,
                level=FirewallSysEvent.LEVEL_MESSAGE,
                start_time=str(current - timedelta(hours=1)),
                end_time=str(current + timedelta(hours=1)),
            )
        )

        assert response.data['count'] == 1


class TestDeviceAlert(BaseViewTest):
    @SecurityEngineerPermission.permission_update
    def test_update_permissions(self, all_client: Dict[str, APIClient],
                                user: str, expect_code: int):
        client = all_client[user]
        alert = DeviceAllAlertFactory.create(status_resolved=0)
        targets = ['batch-resolve-alert', 'resolve-alert', 'resolve-all-alert']
        args = [None, alert.id, None]
        query = [None, None, {'status_resolved': 0}]
        body = [
            {'des_resolved': '2334', 'status_resolved': 1, 'ids': []},
            {'des_resolved': '1234', 'status_resolved': 1},
            {'des_resolved': '3234', 'status_resolved': 1},
        ]

        for i in range(len(targets)):
            if args[i]:
                url = reverse(targets[i], args=(args[i], ))
            elif query[i]:
                url = reverse(targets[i]) + '?status_resolved=0'
            else:
                url = reverse(targets[i])
            response = client.put(url, data=body[i], format='json')
            assert response.status_code == expect_code

    def test_resolve_alert(self, security_client: APIClient):
        alert = DeviceAllAlertFactory.create(status_resolved=0)
        response = security_client.put(
            reverse('resolve-alert', args=(alert.id, )),
            data=dict(
                des_resolved='放飞小高',
                status_resolved=1,
            ),
            format='json'
        )
        assert DeviceAllAlert.objects.filter(
            id=alert.id, des_resolved='放飞小高', status_resolved=1).exists()

    def test_batch_resolve_alert(self, security_client: APIClient):
        alerts = DeviceAllAlertFactory.create_batch(20, status_resolved=0)
        ids = [a.id for a in alerts]
        response = security_client.put(
            reverse('batch-resolve-alert'),
            data=dict(
                ids=ids,
                des_resolved='放飞小高',
                status_resolved=1,
            ),
            format='json'
        )

        assert DeviceAllAlert.objects.filter(
            id__in=ids, des_resolved='放飞小高', status_resolved=1,
        ).count() == 20

    def test_resolve_all_alert(self, security_client: APIClient):
        device = DeviceFactory.create_normal(name='小高起飞')
        current = timezone.now()
        alerts = DeviceAllAlertFactory.create_batch(
            10, device=device, level=1, type=1, status_resolved=0,
            category=1, occurred_time=current
        )

        query = dict(
            device_name='小高起飞', level=1, category=1, status_resolved=0,
            type=1, start_time=str(current - timedelta(hours=1)),
            end_time=str(current + timedelta(hours=1))
        )
        response = security_client.put(
            reverse('resolve-all-alert') + '?{}'.format(urlencode(query)),
            data={'des_resolved': '放飞小高', 'status_resolved': 1},
            format='json'
        )

        assert DeviceAllAlert.objects.filter(
            device__name='小高起飞', level=1, category=1, status_resolved=1,
            type=1, des_resolved='放飞小高').count() == 10


class TestSecurityEvent(BaseViewTest):
    @SecurityEngineerPermission.permission_update
    def test_update_permissions(self, all_client: Dict[str, APIClient],
                                user: str, expect_code: int):
        client = all_client[user]
        alert = SecurityEventFactory.create(status_resolved=0)
        targets = ['batch-resolve-security', 'resolve-security',
                   'resolve-all-security']
        args = [None, alert.id, None]
        query = [None, None, {'status_resolved': 0}]
        body = [
            {'des_resolved': '2334', 'status_resolved': 1, 'ids': []},
            {'des_resolved': '1234', 'status_resolved': 1},
            {'des_resolved': '3234', 'status_resolved': 1},
        ]

        for i in range(len(targets)):
            if args[i]:
                url = reverse(targets[i], args=(args[i], ))
            elif query[i]:
                url = reverse(targets[i]) + '?status_resolved=0'
            else:
                url = reverse(targets[i])
            response = client.put(url, data=body[i], format='json')
            assert response.status_code == expect_code

    def test_resolve_alert(self, security_client: APIClient):
        alert = DeviceAllAlertFactory.create(status_resolved=0)
        response = security_client.put(
            reverse('resolve-alert', args=(alert.id, )),
            data=dict(
                des_resolved='放飞小高',
                status_resolved=1,
            ),
            format='json'
        )
        assert DeviceAllAlert.objects.filter(
            id=alert.id, des_resolved='放飞小高', status_resolved=1).exists()

    def test_batch_resolve_alert(self, security_client: APIClient):
        alerts = SecurityEventFactory.create_batch(20, status_resolved=0)
        ids = [a.id for a in alerts]
        response = security_client.put(
            reverse('batch-resolve-security'),
            data=dict(
                ids=ids,
                des_resolved='放飞小高',
                status_resolved=1,
            ),
            format='json'
        )

        assert SecurityEvent.objects.filter(
            id__in=ids, des_resolved='放飞小高', status_resolved=1,
        ).count() == 20

    def test_resolve_all_alert(self, security_client: APIClient):
        device = DeviceFactory.create_normal(name='小高起飞')
        current = timezone.now()
        alerts = SecurityEventFactory.create_batch(
            10, device=device, level=1, type=1, status_resolved=0,
            category=1, occurred_time=current
        )

        query = dict(
            device_name='小高起飞', level=1, category=1, status_resolved=0,
            type=1, start_time=str(current - timedelta(hours=1)),
            end_time=str(current + timedelta(hours=1))
        )
        response = security_client.put(
            reverse('resolve-all-security') + '?{}'.format(urlencode(query)),
            data={'des_resolved': '放飞小高', 'status_resolved': 1},
            format='json'
        )

        assert SecurityEvent.objects.filter(
            device__name='小高起飞', level=1, category=1, status_resolved=1,
            type=1, des_resolved='放飞小高').count() == 10
