import pytest

from utils.unified_redis import rs
from log.models import UnifiedForumLog, DeviceAllAlert
from setting.system_check import CPUCheck
from log.security_event import CPUEvent


@pytest.mark.django_db
class TestCPUCheck:
    @pytest.fixture(scope='function')
    def clean_cache(self):
        rs.delete(CPUCheck.exceed_key)
        rs.delete(CPUCheck.alert_key)
        return None

    def test_add_exceed_count(self, clean_cache):
        cpu_check = CPUCheck(10)

        cpu_check.add_exceed_count()
        assert int(rs.get(CPUCheck.exceed_key)) == 1

        for _ in range(10):
            cpu_check.add_exceed_count()
        assert int(rs.get(CPUCheck.exceed_key)) == 11

    def test_need_to_alert(self, clean_cache):
        cpu_check = CPUCheck(10)
        cpu_check.set_alert_status()

        assert cpu_check.need_to_alert(1000) is False

        rs.delete(CPUCheck.alert_key)
        assert cpu_check.need_to_alert(1000) is True

    def test_generate_alarm(self, clean_cache):
        cpu_check = CPUCheck(10)
        cpu_check.generate_alarm()

        assert UnifiedForumLog.objects.filter(
            content__contains='CPU使用率').exists()
        assert CPUEvent.get_queryset(content__contains='CPU使用率').exists()
        assert cpu_check.get_alert_status()

    def test_check_with_alarm(self, clean_cache):
        cpu_check = CPUCheck(-1)
        rs.set(CPUCheck.exceed_key, 20)
        cpu_check.check()

        assert UnifiedForumLog.objects.filter(
            content__contains='CPU使用率').exists()
        assert CPUEvent.get_queryset(content__contains='CPU使用率').exists()
        assert cpu_check.get_alert_status()

    def test_check_without_alarm(self, clean_cache):
        cpu_check = CPUCheck(100)
        rs.set(CPUCheck.exceed_key, 20)
        cpu_check.check()

        assert not UnifiedForumLog.objects.filter(
            content__contains='CPU使用率').exists()
        assert not CPUEvent.get_queryset(content__contains='CPU使用率').exists()
        assert not cpu_check.get_alert_status()

    def test_check_complex(self, clean_cache):
        """
        模拟流程:
        1. 产生了告警
        2. 告警期间内，不再统计exceed_count
        3. 告警结束后，重新统计
        4. 统计达标后，产生告警
        """
        cpu_check = CPUCheck(-1)
        rs.set(CPUCheck.exceed_key, 10)
        # 1. 产生了告警
        cpu_check.set_alert_status()

        # 2. 告警期间内不统计exceed_count
        cpu_check.check()
        assert not rs.get(CPUCheck.exceed_key)

        # 3. 告警结束，重新统计
        rs.delete(CPUCheck.alert_key)
        cpu_check.check()
        assert int(rs.get(CPUCheck.exceed_key)) == 1

        # 4. 统计达标后，产生告警
        rs.set(CPUCheck.exceed_key, 20)
        cpu_check.check()

        assert UnifiedForumLog.objects.filter(
            content__contains='CPU使用率').exists()
        assert CPUEvent.get_queryset(content__contains='CPU使用率').exists()
        assert cpu_check.get_alert_status()