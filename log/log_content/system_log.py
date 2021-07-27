"""
系统管理日志
"""
from typing import List, Tuple

from log.log_content.log_generator import LogGenerator, LogConfig, HookAbstract
from log.models import UnifiedForumLog
from setting.models import Setting
from log.security_event import IPSettingLog

system_config = LogConfig()

IP = str


class SystemLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_SYSTEM,
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION


@system_config.register('setting-ip', 'POST')
class SettingIpLogGenerator(SystemLogMixin, LogGenerator):
    """
    设置IP的操作日志
    日志格式:
    设置了IP信息: IP地址【】，网关【】，子网掩码【】
    """
    content_template = ('设置了IP信息: IP地址{address}，网关{gateway}，'
                        '子网掩码{net_mask}，{result}')

    def get_content(self) -> str:
        """
        :return: 设置了IP信息: IP地址192.11.1.1，网关192.168.0.1，子网掩码255.0.0.1
        """
        content = self.content_template.format(
            address=self.request_body['address'],
            gateway=self.request_body['gateway'],
            net_mask=self.request_body['net_mask'],
            result=self.resp_result,
        )
        return content


@system_config.register('setting-time', 'POST')
class SettingTimeLogGenerator(SystemLogMixin, LogGenerator):
    """
    设置时间的操作日志
    日志格式:
    设置NTP服务器地址: 【】
    """
    content_template = '设置NTP服务器地址: {ntp}, {result}'

    def get_content(self):
        """
        :return: 设置NTP服务器地址: 192.168.0.1
        """
        content = self.content_template.format(
            ntp=self.request_body['ntp'],
            result=self.resp_result,
        )
        return content


@system_config.register('setting', 'PATCH')
class SettingLogGenerator(SystemLogMixin, LogGenerator):
    """
    设置登录安全的日志
    日志格式:
    设置了登录安全信息：无操作自动【】分钟退出，密码输入错误【】次锁定，锁定时长【】分钟，未更换密码告警提醒【】天
    """
    content_template = {
        'lockout_threshold': '密码错误阈值设置为{setting}次, {result}',
        'lockout_duration': '账号锁定时长设置为{setting}分钟, {result}',
        'login_timeout_duration': '无操作自动退出设置{setting}分钟，{result}',
        'change_psw_duration': '未更换密码告警提醒{setting}天, {result}'
    }

    def _get_content(self, key: str, setting: int) -> str:
        return self.content_template[key].format(
            setting=setting, result=self.resp_result
        )

    def get_content(self):
        return None

    def generate_log(self):
        data = self.request_body
        for key in data.keys():
            template = self.get_data()
            template['content'] = self._get_content(key, data[key])
            self.log_cls.objects.create(**template)


@system_config.register('system-security', 'PATCH')
class SettingLogGenerator(SystemLogMixin, LogGenerator):
    """
    设置系统安全的日志
    日志格式:
    存储使用告警设置为90%
    存储使用覆盖设置为90%
    CPU使用告警设置为90%
    内存使用告警设置为90%
    """
    content_template = {
        'disk_alert_percent': '存储使用告警设置为{setting}%, {result}',
        'disk_clean_percent': '存储使用覆盖设置为{setting}%, {result}',
        'cpu_alert_percent': 'CPU使用告警设置为{setting}%，{result}',
        'memory_alert_percent': '内存使用告警设置为{setting}%, {result}'
    }

    def _get_content(self, key: str, setting: int) -> str:
        return self.content_template[key].format(
            setting=setting, result=self.resp_result
        )

    def get_content(self):
        return None

    def generate_log(self):
        data = self.request_body
        for key in data.keys():
            template = self.get_data()
            template['content'] = self._get_content(key, data[key])
            self.log_cls.objects.create(**template)


@system_config.register('ip-limit', 'PATCH', additional_info=True)
class IpLimitLogGenerator(SystemLogMixin, LogGenerator, HookAbstract):
    """
    远程登录设置日志
    日志格式:
    设置了IP远程登录信息：禁止所有IP/允许所有IP/允许指定IP
    """
    content_template = '远程登录设置: {setting}, {result}'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.item: Setting = kwargs['item']

    def get_setting(self):
        if not self.request_body['ip_limit_enable']:
            return '允许所有IP'
        else:
            add, delete = self.get_add_delete()
            return '允许指定IP，增加{add}, 删除{delete}'.format(
                add=', '.join(add), delete=', '.join(delete)
            )

    def get_content(self):
        content = self.content_template.format(
            setting=self.get_setting(),
            result=self.resp_result,
        )
        return content

    @classmethod
    def get_previous(cls, request):
        setting = Setting.objects.get()
        return {'item': setting}

    def get_add_delete(self) -> Tuple[List[IP], List[IP]]:
        """
        :return 返回本次增加的ip列表和删除的ip列表
        """
        previous = set(self.item.allowed_ip)
        current = set(self.request_body['allowed_ip'])
        union = previous & current

        add = list(current - union)
        delete = list(previous - union)

        return add, delete

    def generate_log(self):
        event = IPSettingLog(content=self.get_content())
        event.generate()
        return super().generate_log()


@system_config.register('setting-theme', 'PATCH')
class ThemeSettingLogGenerator(LogGenerator):
    data_template = {
        'type': UnifiedForumLog.TYPE_THEME,
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION

    content_template = ('设置背景色为{background}, 主题色为{theme},'
                        ' {result}')

    background_map = {
        'dark': '深色背景',
        'light': '浅色背景'
    }

    theme_map = {
        'green': '绿色',
        'blue': '蓝色',
        'red': '红色',
        'orange': '橘色',
    }

    def get_content(self):
        data = self.request_body
        return self.content_template.format(
            background=self.background_map[data['background']],
            theme=self.theme_map[data['theme']],
            result=self.resp_result
        )


@system_config.register('setting-location', 'post')
class LocationSettingLogGenerator(LogGenerator):
    data_template = {
        'type': UnifiedForumLog.TYPE_SYSTEM
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION

    content_template = '设置系统所在城市为: {city}'

    def get_content(self):
        city = self.request_body['city']
        return self.content_template.format(city=city)


@system_config.register('security-center-clean', 'patch')
class SecurityCenterCleanLogGenerator(LogGenerator):
    data_template = {
        'type': UnifiedForumLog.TYPE_SYSTEM
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION

    content_template = '设置安全中心统计数据清理时间为: {cycle}个月'

    def get_content(self):
        cycle = self.request_body['security_center']
        return self.content_template.format(cycle=cycle)
