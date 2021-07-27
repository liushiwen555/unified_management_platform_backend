import psutil

from log.models import UnifiedForumLog
from setting.system_check.base_check import BaseCheck
from log.security_event import MemoryEvent


class MemoryCheck(BaseCheck):
    exceed_key = 'memory_alert_exceed_count'
    alert_key = 'memory_alert_status'
    event_class = MemoryEvent
    """
    检查内存使用率，并根据用户设置，触发告警数据
    """

    def __init__(self, threshold: int, alert_threshold=20, expire_time=300,
                 countdown=600):
        super().__init__(threshold, alert_threshold, expire_time, countdown)

    def get_percent(self) -> float:
        return psutil.virtual_memory().percent

    def generate_alarm(self):
        content = f'内存使用率达到{self.threshold}%'
        UnifiedForumLog.objects.create(
            type=UnifiedForumLog.TYPE_MEMORY,
            content=content,
            result=True,
            category=UnifiedForumLog.CATEGORY_SYSTEM,
            ip='127.0.0.1'
        )
        self.generate_security_event(content=content)
        self.set_alert_status()
