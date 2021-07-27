import pytest
from django.utils import timezone

from statistic.models import SystemRunning
from statistic.tasks import SystemRunningTask


@pytest.mark.django_db
class TestSystemRunningTask:
    def test_system_running(self):
        data = SystemRunningTask.run(timezone.now())

        assert SystemRunning.objects.first().id == data.id
