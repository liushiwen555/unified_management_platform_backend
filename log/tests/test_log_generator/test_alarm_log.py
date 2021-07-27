from typing import Dict

from django.urls import reverse
from rest_framework.test import APIClient
from django.utils.http import urlencode

from log.factory_data import DeviceAllAlertFactory, SecurityEventFactory
from log.models import UnifiedForumLog, DeviceAllAlert, SecurityEvent
from log.tests.test_log_generator.base_testcase import BaseLogTest


class TestAlarmLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_ALARM
    category = UnifiedForumLog.CATEGORY_OPERATION

    factory = DeviceAllAlertFactory
    model = DeviceAllAlert

    ALERT_RESOLVE = 'resolve-alert'
    BATCH_ALERT_RESOLVE = 'batch-resolve-alert'
    ALL_ALERT_RESOLVE = 'resolve-all-alert'

    def format_content(self, method: str, id: int, status_code: int,
                       count: int = None, query: Dict = None):
        if not count:
            return '{method}了 {id} 号安全威胁, {result}'.format(
                method=method, id=id, result=self.status_desc(status_code))
        else:
            return '{method}了 {id} 号等{count}条安全威胁, {result}'.format(
                method=method, id=id, count=count,
                result=self.status_desc(status_code)
            )

    def test_alert_resolve(self, engineer_client: APIClient):
        """
        处理了【序号】号安全威胁
        """
        alert = self.factory.create(
            status_resolved=self.model.STATUS_UNRESOLVED)
        response = engineer_client.put(
            reverse(self.ALERT_RESOLVE, args=(alert.id,)),
            data={
                'status_resolved': 1,
            },
            format='json'
        )
        log = UnifiedForumLog.objects.filter(
            content=self.format_content('处理', alert.id, response.status_code))
        assert log.exists() is True
        self.check_type_and_category(log[0])

    def test_batch_alert_resolve(self, engineer_client: APIClient):
        """
        批量处理了【序号】号等【X】条安全威胁
        """
        alerts = self.factory.create_batch(
            size=20, status_resolved=self.model.STATUS_UNRESOLVED)
        ids = [a.id for a in alerts]

        response = engineer_client.put(
            reverse(self.BATCH_ALERT_RESOLVE),
            data={
                'ids': ids,
                'status_resolved': 1,
                'des_resolved': '',
            },
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '批量处理', ids[0], response.status_code, count=len(ids),
        ))

        assert log.exists()
        self.check_type_and_category(log[0])

    def test_resolve_all_alert(self, engineer_client: APIClient):
        alerts = self.factory.create_batch(
            10, level=1, type=1, status_resolved=0, category=1)

        query = dict(level='1', category='1', status_resolved='0', type='1')
        queryset = self.model.objects.filter(
            level=1, category=1, status_resolved=0, type=1
        )
        first_id = queryset.first().id
        count = queryset.count()
        assert count == 10

        url = reverse(self.ALL_ALERT_RESOLVE) + '?{}'.format(urlencode(query))
        response = engineer_client.put(
            url,
            data={'des_resolved': '放飞小高', 'status_resolved': 1},
            format='json'
        )

        content = self.format_content('批量处理', first_id, response.status_code,
                                      count=count)

        log = UnifiedForumLog.objects.filter(content=content)

        assert log.exists()
        self.check_type_and_category(log[0])


class TestSecurityEventLog(TestAlarmLog):
    factory = SecurityEventFactory
    model = SecurityEvent

    ALERT_RESOLVE = 'resolve-security'
    BATCH_ALERT_RESOLVE = 'batch-resolve-security'
    ALL_ALERT_RESOLVE = 'resolve-all-security'

    def format_content(self, method: str, id: int, status_code: int,
                       count: int = None, query: Dict = None):
        if not count:
            return '{method}了 {id} 号安全事件, {result}'.format(
                method=method, id=id, result=self.status_desc(status_code))
        else:
            return '{method}了 {id} 号等{count}条安全事件, {result}'.format(
                method=method, id=id, count=count,
                result=self.status_desc(status_code)
            )