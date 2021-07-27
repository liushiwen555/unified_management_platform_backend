import pytest
from django.utils import timezone

from statistic.tasks import AssetsIPDistributionTask


@pytest.mark.django_db
class TestAssetsIPDistributionTask:
    def test_task(self):
        t = timezone.now()
        result = AssetsIPDistributionTask.run(t)

        assert result.update_time >= t

    def test_analyze_ip_distribution(self):
        ips = ['192.168.1.1', '192.168.1.2', '10.0.2.2', '10.0.1.192']

        distribution = AssetsIPDistributionTask.analyze_ip_distribution(ips)

        assert distribution == {
            '192.168.1.1/24': ['192.168.1.1', '192.168.1.2'],
            '10.0.2.1/24': ['10.0.2.2'],
            '10.0.1.1/24': ['10.0.1.192'],
        }
