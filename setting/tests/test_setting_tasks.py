from datetime import timedelta

import pytest
from django.utils import timezone

from log.models import UnifiedForumLog
from setting.models import Setting
from setting.tasks import StatisticDataCleanTask
from statistic.factory_data import LogCenterFactory
from statistic.models import LogCenter


@pytest.mark.django_db
class TestCleanStatisticData:
    """
    测试定时清理安全中心历史统计数据
    """
    def test_clean(self):
        current = timezone.now()
        setting, _ = Setting.objects.get_or_create(id=1)
        log1 = LogCenterFactory.create(update_time=current - timedelta(
            days=setting.security_center * 30 + 1))
        log2 = LogCenterFactory.create(update_time=current - timedelta(days=29))

        StatisticDataCleanTask.run(current)
        assert LogCenter.objects.count() == 1
        assert LogCenter.objects.first().id == log2.id
        assert UnifiedForumLog.objects.filter(
            content__contains='前的安全中心统计数据').exists()
