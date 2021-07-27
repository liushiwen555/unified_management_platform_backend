import pytest
from django.utils import timezone

from unified_management_platform.scheduler import *


@pytest.mark.django_db
class TestScheduler:
    def test_scheduler(self):
        ip_duplicate_clean_task()
        task_run_every_day()
        task_run_every_60_minutes()
        task_run_every_2_minutes()
        task_run_every_5_seconds()
        task_run_every_minute()
        task_run_every_10_minutes()
        task_run_every_30_minutes()
