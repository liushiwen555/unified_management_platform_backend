from abc import ABC, abstractmethod
from typing import Type

from log.security_event import EventLog
from utils.unified_redis import rs


class BaseCheck(ABC):
    exceed_key = 'alert_exceed_count'
    alert_key = 'alert_status'
    event_class: Type[EventLog] = None
    """
    检查使用率，并根据用户设置，处罚告警数据
    """

    def __init__(self, threshold: int, alert_threshold=20, expire_time=300,
                 countdown=600):
        """
        :param threshold: 利用率阈值
        :param alert_threshold: 告警阈值，利用率超阈值次数大于alert_threshold
        会触发告警
        :param expire_time: 统计超过限制的时间
        :param countdown: XX分钟内不产生同类告警
        """
        self.threshold = threshold
        self.alert_threshold = alert_threshold
        self._expire_time = expire_time
        self._countdown = countdown

    @abstractmethod
    def generate_alarm(self):
        pass

    @abstractmethod
    def get_percent(self) -> float:
        pass

    def exceed_threshold(self) -> bool:
        """
        判断是否超过使用阈值
        :return: True or False
        """
        return (self.get_percent() > self.threshold and
                not self.get_alert_status())

    def add_exceed_count(self) -> int:
        """
        增加缓存内的超过阈值的次数，并返回当前有多少次
        :return: 当前周期内有多少次超阈值
        """
        if rs.get(self.exceed_key):
            res = rs.incr(self.exceed_key)
            rs.expire(self.exceed_key, self._expire_time)
        else:
            res = rs.incr(self.exceed_key)
        return int(res)

    def set_alert_status(self):
        rs.delete(self.exceed_key)
        rs.set(self.alert_key, 1, ex=self._countdown)

    def get_alert_status(self):
        return 1 if rs.get(self.alert_key) else 0

    def need_to_alert(self, count: int) -> bool:
        """
        根据周期内超阈值的次数，判断是否要生成告警
        :param count: 超阈值的次数
        :return: True or False
        """
        if self.get_alert_status():
            return False
        else:
            return count > self.alert_threshold

    def check(self):
        if not self.exceed_threshold():
            return
        count = self.add_exceed_count()
        if self.need_to_alert(count):
            self.generate_alarm()

    def generate_security_event(self, **kwargs):
        if not self.event_class:
            raise RuntimeError('必须有EventLog类')
        event = self.event_class(**kwargs)
        event.generate()
