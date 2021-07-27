import psutil

from log.models import UnifiedForumLog
from log.security_event import CPUEvent
from setting.system_check.base_check import BaseCheck


class CPUCheck(BaseCheck):
    exceed_key = 'cpu_alert_exceed_count'
    alert_key = 'cpu_alert_status'
    event_class = CPUEvent
    """
    检查CPU使用率，并根据用户设置，处罚告警数据
    """

    def __init__(self, threshold: int, alert_threshold=20, expire_time=300,
                 countdown=600):
        super().__init__(threshold, alert_threshold, expire_time, countdown)

    def get_percent(self) -> float:
        return psutil.cpu_percent()

    def generate_alarm(self):
        content = f'CPU使用率达到{self.threshold}%'
        UnifiedForumLog.objects.create(
            type=UnifiedForumLog.TYPE_CPU,
            content=content,
            result=True,
            category=UnifiedForumLog.CATEGORY_SYSTEM,
            ip='127.0.0.1'
        )
        self.generate_security_event(content=content)
        self.set_alert_status()
