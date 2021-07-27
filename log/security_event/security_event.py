from abc import ABC, abstractmethod
from typing import Optional
from datetime import datetime, time, timedelta

from django.utils import timezone
from django.db.models import Avg

from log.models import SecurityEvent
from base_app.models import Device
from user.models import User, UserExtension
from utils.helper import get_today
from statistic.models import LogStatisticDay
from snmp.models import SNMPData


class EventLog(ABC):
    category = None
    type = None
    level = None

    def __init__(self,
                 device: Optional[Device] = None,
                 user: Optional[User] = None,
                 **kwargs):
        self.device = device
        self.user = user
        self.content = self.get_content(**kwargs)

    def generate(self) -> SecurityEvent:
        return SecurityEvent.objects.create(
            device=self.device,
            level=self.level,
            category=self.category,
            type=self.type,
            content=self.content
        )

    def get_content(self, **kwargs) -> str:
        return kwargs.get('content')

    @classmethod
    def get_queryset(cls, **kwargs):
        return SecurityEvent.objects.filter(
            category=cls.category, type=cls.type, level=cls.level, **kwargs)

    def exists(self, **kwargs):
        return self.get_queryset(**kwargs).exists()


class AssetsEventLog(EventLog):
    """
    需要在资产被删除之前记录
    """
    content = '删除 【{id}-{name}】'
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_OPERATION
    level = SecurityEvent.LEVEL_HIGH

    def get_content(self, device_id, device_name) -> str:
        return self.content.format(id=device_id, name=device_name)


class IPSettingLog(EventLog):
    """
    远程登录设置修改
    """
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_OPERATION
    level = SecurityEvent.LEVEL_HIGH


class RebootEvenLog(EventLog):
    """
    远程登录设置修改
    """
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_ASSETS
    level = SecurityEvent.LEVEL_LOW


class UserEventLog(EventLog):
    """
    用户管理
    """
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_USER
    level = SecurityEvent.LEVEL_LOW


class PasswordErrorEventLog(EventLog):
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_USER
    level = SecurityEvent.LEVEL_MEDIUM

    def get_content(self, threshold=None, lockout_duration=None) -> str:
        return f'密码输入错误{threshold}次，账号锁定{lockout_duration}分钟'

    def generate(self) -> SecurityEvent:
        # 密码输入错误过多，产生新的事件
        event = PasswordErrorExceedEvent(today=timezone.now())
        event.generate()
        return super().generate()


class PasswordErrorExceedEvent(EventLog):
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_USER
    level = SecurityEvent.LEVEL_HIGH
    threshold = 5

    def __init__(self, *args, **kwargs):
        self.today = kwargs['today']
        super().__init__(*args, **kwargs)

    def get_content(self, **kwargs) -> str:
        return f'当天因密码错误锁定账户数达{self.threshold}个'

    def generate(self) -> Optional[SecurityEvent]:
        if self.exists():
            return None
        if not self.should_generate():
            return None

        return super().generate()

    def exists(self):
        return self.get_queryset(
            content=self.content, occurred_time__gte=self.today).exists()

    def should_generate(self) -> bool:
        """
        当天密码错误账户个数是否超过阈值
        """
        count = UserExtension.objects.filter(
            last_failure__gte=get_today(timezone.now()), banned=True).count()
        return count >= self.threshold


class UnModifiedPasswordEvent(EventLog):
    """
    当前因密码使用天数达到阈值告警的账户数达5个
    可以在定时任务执行之后执行这个事件的判断
    """
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_USER
    level = SecurityEvent.LEVEL_MEDIUM
    threshold = 5

    def get_content(self, **kwargs) -> str:
        return f'当前因密码使用天数达到阈值告警的账户数达{self.threshold}个'

    def generate(self) -> Optional[SecurityEvent]:
        count = User.objects.filter(un_modify_passwd=True).count()
        if count >= self.threshold:
            return super().generate()
        return None


class AbnormalLoginEvent(EventLog):
    """
    22:00-6:00期间主动登陆的账户
    UTC事件就是14:00-22:00
    """
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_USER
    level = SecurityEvent.LEVEL_HIGH
    start = time(14)
    end = time(22)
    time_format = '%Y-%m-%d %H:%M:%S'

    def __init__(self, *args, **kwargs):
        self.current = kwargs.get('current') or timezone.now()
        self.username = kwargs.get('username')
        super().__init__(*args, **kwargs)

    def get_content(self, **kwargs) -> str:
        return f'{self.username}于' \
               f'{timezone.localtime(self.current).strftime(self.time_format)}' \
               f'时间请求登录'

    def generate(self) -> Optional[SecurityEvent]:
        if self.start <= self.current.time() <= self.end:
            return super().generate()
        return None


class CPUEvent(EventLog):
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_SYSTEM
    level = SecurityEvent.LEVEL_LOW


class MemoryEvent(EventLog):
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_SYSTEM
    level = SecurityEvent.LEVEL_LOW


class DiskEvent(EventLog):
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_SYSTEM
    level = SecurityEvent.LEVEL_LOW

    def get_content(self, **kwargs) -> str:
        return f'存储空间使用达到阈值{kwargs.get("percent")}'


class DiskCleanEvent(EventLog):
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_SYSTEM
    level = SecurityEvent.LEVEL_LOW

    def get_content(self, **kwargs) -> str:
        return f'存储空间使用达到阈值{kwargs.get("percent")}，覆盖历史数据'


class AssetsOfflineEvent(EventLog):
    category = SecurityEvent.CATEGORY_OPERATION
    type = SecurityEvent.TYPE_ASSETS
    level = SecurityEvent.LEVEL_MEDIUM

    def get_content(self, **kwargs) -> str:
        return '资产离线'


class NetworkEvent(EventLog):
    """
    流量速度为0，持续5分钟
    """
    category = SecurityEvent.CATEGORY_LOCAL
    type = SecurityEvent.TYPE_SYSTEM
    level = SecurityEvent.LEVEL_MEDIUM
    duration = 5

    def get_content(self, **kwargs) -> str:
        return f'{kwargs.get("name")}网口连接异常'

    def generate(self) -> Optional[SecurityEvent]:
        current = timezone.now()
        last = current - timedelta(minutes=self.duration)
        if self.get_queryset(content=self.content, occurred_time__gt=last
                             ).exists():
            return None
        super().generate()


class SecurityEventLog(EventLog):
    """
    未处理的安全事件达到1000条，未处理的安全威胁1000条
    """
    category = SecurityEvent.CATEGORY_OPERATION
    type = SecurityEvent.TYPE_SECURITY
    level = SecurityEvent.LEVEL_MEDIUM
    threshold = 1000

    def __init__(self, count, *args, **kwargs):
        self.count = count
        super().__init__(*args, **kwargs)

    def get_content(self, **kwargs) -> str:
        return f'未处理的安全事件达到{self.threshold}条'

    def generate(self) -> Optional[SecurityEvent]:
        if self.count >= self.threshold:
            return super().generate()
        return None


class AlertEvent(SecurityEventLog):
    def get_content(self, **kwargs) -> str:
        return f'未处理的安全威胁达到{self.threshold}条'


class HighAlertEvent(SecurityEventLog):
    category = SecurityEvent.CATEGORY_OPERATION
    type = SecurityEvent.TYPE_SECURITY
    level = SecurityEvent.LEVEL_HIGH
    threshold = 500

    def get_content(self, **kwargs) -> str:
        return f'未处理的高级安全威胁达到{self.threshold}条'


class _AssetsEvent(EventLog):
    category = SecurityEvent.CATEGORY_OPERATION
    type = SecurityEvent.TYPE_ASSETS
    level = SecurityEvent.LEVEL_LOW
    threshold = 80

    def __init__(self, usage, *args, **kwargs):
        self.usage = usage
        super().__init__(*args, **kwargs)

    def generate(self) -> Optional[SecurityEvent]:
        if not self.device:
            raise AttributeError('没有资产')
        if self.usage < self.threshold:
            return None
        return super().generate()


class AssetsCPUEvent(_AssetsEvent):
    def get_content(self, **kwargs) -> str:
        return f'资产CPU使用率达到阈值{self.threshold}%'


class AssetsMemoryEvent(_AssetsEvent):
    def get_content(self, **kwargs) -> str:
        return f'资产内存使用率达到阈值{self.threshold}%'


class AssetsDiskEvent(_AssetsEvent):
    def get_content(self, **kwargs) -> str:
        return f'资产分区{kwargs.get("partition")}使用率达到阈值{self.threshold}%'


class LogAbnormalEvent(EventLog):
    """
    今日日志超过过去7天平均的100%
    """
    category = SecurityEvent.CATEGORY_OPERATION
    type = SecurityEvent.TYPE_ABNORMAL
    level = SecurityEvent.LEVEL_MEDIUM

    def __init__(self, count, current: datetime, *args, **kwargs):
        self.count = count
        self.today = get_today(current)
        super().__init__(*args, **kwargs)

    def get_content(self, **kwargs) -> str:
        return f'今日日志数量异常'

    def is_abnormal(self) -> bool:
        """
        如果今日日志超过过去7天平均的100%，判断为异常
        7天平均 * 2 < 今日 ==> 异常
        :return:
        """
        avg = LogStatisticDay.objects.filter(
            update_time__gte=self.today - timedelta(days=7),
            update_time__lt=self.today,
        ).aggregate(local=Avg('local_today'), collect=Avg('collect_today'))
        avg_total = (avg['local'] or 0) + (avg['collect'] or 0)
        if avg_total * 2 < self.count:
            return True
        return False

    def generate(self) -> Optional[SecurityEvent]:
        """
        今天已经有安全事件或者数据不异常，就不用生成安全事件
        :return:
        """
        if self.get_queryset(
                content=self.content, occurred_time__gte=self.today
        ).exists() or not self.is_abnormal():
            return None
        return super().generate()


class ProcessEvent(EventLog):
    """
    进程数超过过去7天平均的100%
    """
    category = SecurityEvent.CATEGORY_OPERATION
    type = SecurityEvent.TYPE_ASSETS
    level = SecurityEvent.LEVEL_MEDIUM

    def __init__(self, count: int, current: datetime, *args, **kwargs):
        self.count = count
        self.current = current
        self.today = get_today(current)
        super().__init__(*args, **kwargs)

    def get_content(self, **kwargs) -> str:
        return '进程数量异常'

    def generate(self) -> Optional[SecurityEvent]:
        """
        每天只产生一条
        :return:
        """
        if self.exists(
                device_id=self.device.id, content=self.content,
                occurred_time__gte=self.today
        ):
            return None
        if not self.is_abnormal():
            return None
        return super().generate()

    def is_abnormal(self):
        """
        如果今日进程超过过去7天平均的100%，判断为异常
        7天平均 * 2 < 今日 ==> 异常
        :return:
        """
        avg = SNMPData.objects.filter(
            device=self.device,
            update_time__gte=self.current-timedelta(hours=7),
            update_time__lt=self.current
        ).aggregate(process=Avg('process_count'))
        process_count = avg['process'] or 0
        if process_count * 2 < self.count:
            return True
        return False
