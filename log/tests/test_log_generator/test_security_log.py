from datetime import datetime

from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from log.factory_data import ReportLogFactory
from log.models import UnifiedForumLog, ReportLog
from log.tests.test_log_generator.base_testcase import BaseLogTest


class TestSecurityLog(BaseLogTest):
    content_template = '{method}了 {id} 号报表, {result}'
    type = UnifiedForumLog.TYPE_SECURITY
    category = UnifiedForumLog.CATEGORY_OPERATION

    REPORT_LOG_DOWNLOAD = 'download-report-log'
    REPORT_LOG_POST = 'report-log-list'
    REPORT_LOG_DELETE = 'report-log-detail'

    def format_content(self, method: str, id: int, status_code: int):
        if status.is_success(status_code):
            return self.content_template.format(
                method=method, id=id, result='成功')
        else:
            return self.content_template.format(
                method=method, id=id, result='失败'
            )

    def test_report_log_download(self, audit_client: APIClient):
        """
        下载了【序号】号报表
        """
        report = ReportLogFactory.create()

        response = audit_client.get(
            reverse(self.REPORT_LOG_DOWNLOAD, args=(report.id,)),
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '下载', report.id, response.status_code))
        assert log.exists() is True
        self.check_type_and_category(log[0])

    def test_report_log_list(self, engineer_client: APIClient):
        """
        添加了【序号】号报表
        """
        response = engineer_client.post(
            reverse(self.REPORT_LOG_POST),
            data={
                'start_time': '2020-09-02T00:00:00.000000+08:00',
                'end_time': '2020-09-10T00:00:00.000000+08:00',
            },
            format='json'
        )

        report = ReportLog.objects.filter(
            start_time=datetime(2020, 9, 1, 16).replace(tzinfo=timezone.utc))[0]

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '添加', report.id, response.status_code
        ))
        assert log.exists() is True
        self.check_type_and_category(log[0])

    def test_report_log_delete(self, engineer_client: APIClient):
        """
        处理了【序号】号告警
        """
        report = ReportLogFactory.create()
        response = engineer_client.delete(
            reverse(self.REPORT_LOG_DELETE, args=(report.id,))
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '删除', report.id, response.status_code
        ))
        assert log.exists() is True
        self.check_type_and_category(log[0])
