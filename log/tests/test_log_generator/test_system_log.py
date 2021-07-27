from django.urls import reverse
from faker import Faker
from rest_framework.test import APIClient

from log.models import UnifiedForumLog
from log.tests.test_log_generator.base_testcase import BaseLogTest
from setting.models import Setting
from utils.base_testcase import BaseUser
from log.security_event import IPSettingLog, RebootEvenLog

fake = Faker()


class TestSettingIpLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_SYSTEM
    category = UnifiedForumLog.CATEGORY_OPERATION
    SETTING_IP = 'setting-ip'

    def format_content(self, address: str, gateway: str, net_mask: str,
                       status_code: int):
        return '设置了IP信息: IP地址{address}，网关{gateway}，子网掩码{net_mask}，' \
               '{result}'.format(address=address, gateway=gateway,
                                 net_mask=net_mask,
                                 result=self.status_desc(status_code))

    def test_setting_ip(self, config_client: APIClient):
        """
        设置了IP信息：IP地址192.168.0.1，子网掩码255.255.255.0，网关192.168.0.1
        """
        data = dict(
            address=fake.ipv4(),
            gateway=fake.ipv4(),
            net_mask=fake.ipv4(),
        )
        response = config_client.post(
            reverse(self.SETTING_IP),
            data=data,
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            data['address'], data['gateway'], data['net_mask'],
            response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestSettingTimeLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_SYSTEM
    category = UnifiedForumLog.CATEGORY_OPERATION

    SETTING_TIME = 'setting-time'

    def format_content(self, ntp: str, status_code: int):
        return '设置NTP服务器地址: {ntp}, {result}'.format(
            ntp=ntp, result=self.status_desc(status_code)
        )

    def test_setting_time(self, config_client: APIClient):
        """
        设置NTP服务器地址: 192.168.0.1
        """
        response = config_client.post(
            reverse(self.SETTING_TIME),
            data={
                'ntp': '192.168.0.1'
            },
            format='json',
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '192.168.0.1', response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestRebootLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_SYSTEM
    category = UnifiedForumLog.CATEGORY_OPERATION

    SETTING_REBOOT = 'setting-reboot'

    def format_content(self, status_code: int):
        return '设备重启, {result}'.format(result=self.status_desc(status_code))

    def test_reboot(self, config_client: APIClient):
        response = config_client.post(
            reverse(self.SETTING_REBOOT),
            data={'password': BaseUser.right_password},
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            response.status_code))

        assert log.exists()
        assert RebootEvenLog.get_queryset(content='设备重启').exists()
        self.check_type_and_category(log[0])


class TestLoginSettingLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_SYSTEM
    category = UnifiedForumLog.CATEGORY_OPERATION

    SETTING = 'setting'

    content_template = {
        'lockout_threshold': '密码错误阈值设置为{setting}次, {result}',
        'lockout_duration': '账号锁定时长设置为{setting}分钟, {result}',
        'login_timeout_duration': '无操作自动退出设置{setting}分钟，{result}',
        'change_psw_duration': '未更换密码告警提醒{setting}天, {result}'
    }

    def format_content(self, key: str, setting: int, status_code: int):
        return self.content_template[key].format(
            setting=setting, result=self.status_desc(status_code)
        )

    def test_setting(self, config_client: APIClient):
        """
        设置了登录安全信息：无操作自动100分钟退出，密码输入错误5次锁定，
        锁定时长100分钟，未更换密码告警提醒90天
        """
        data = dict(
            login_timeout_duration=100,
            lockout_threshold=5,
            lockout_duration=100,
            change_psw_duration=90,
        )

        response = config_client.patch(
            reverse(self.SETTING),
            data=data,
            format='json'
        )

        for key in self.content_template.keys():
            log = UnifiedForumLog.objects.filter(content=self.format_content(
                key, data[key], status_code=response.status_code,
            ))

            assert log.exists()
            self.check_type_and_category(log[0])


class TestSecuritySettingLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_SYSTEM
    category = UnifiedForumLog.CATEGORY_OPERATION

    SETTING = 'system-security'

    content_template = {
        'disk_alert_percent': '存储使用告警设置为{setting}%, {result}',
        'disk_clean_percent': '存储使用覆盖设置为{setting}%, {result}',
        'cpu_alert_percent': 'CPU使用告警设置为{setting}%，{result}',
        'memory_alert_percent': '内存使用告警设置为{setting}%, {result}'
    }

    def format_content(self, key: str, setting: int, status_code: int):
        return self.content_template[key].format(
            setting=setting, result=self.status_desc(status_code)
        )

    def test_setting(self, config_client: APIClient):
        data = {
            'disk_alert_percent': 90,
            'disk_clean_percent': 90,
            'cpu_alert_percent': 90,
            'memory_alert_percent': 90,
        }

        response = config_client.patch(
            reverse(self.SETTING),
            data=data,
            format='json'
        )

        for key in self.content_template.keys():
            log = UnifiedForumLog.objects.filter(content=self.format_content(
                key, data[key], status_code=response.status_code,
            ))

            assert log.exists()
            self.check_type_and_category(log[0])


class TestIpLimitLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_SYSTEM
    category = UnifiedForumLog.CATEGORY_OPERATION

    IP_LIMIT = 'ip-limit'

    def format_content(self, setting: str, status_code: int):
        return '远程登录设置: {setting}, {result}'.format(
            setting=setting, result=self.status_desc(status_code)
        )

    def test_ip_limit(self, config_client: APIClient):
        """
        设置了IP远程登录信息：允许指定IP
        """
        data = {
            'ip_limit_enable': False,
            'allowed_ip': [],
        }

        response = config_client.patch(
            reverse(self.IP_LIMIT),
            data=data,
            format='json'
        )
        content = self.format_content('允许所有IP', response.status_code,)
        log = UnifiedForumLog.objects.filter()

        assert log.exists()
        assert IPSettingLog.get_queryset(content=content)
        self.check_type_and_category(log[0])

        Setting.objects.update(allowed_ip=['1.1.1.1', '2.2.2.2', '3.3.3.3'])
        data['ip_limit_enable'] = True
        data['allowed_ip'] = ['127.0.0.1', '2.2.2.2', '4.4.4.4']

        response = config_client.patch(
            reverse(self.IP_LIMIT),
            data=data,
            format='json'
        )
        log = UnifiedForumLog.objects.filter(content__contains='允许指定IP')

        assert log.exists()
        assert IPSettingLog.get_queryset(content__contains='允许指定IP')
        self.check_type_and_category(log[0])


class TestThemeSettingLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_THEME
    category = UnifiedForumLog.CATEGORY_OPERATION

    THEME_SETTING = 'setting-theme'

    def format_content(self, background: str, theme: str, status_code: int):
        return f'设置背景色为{background}, 主题色为{theme},' \
               f' {self.status_desc(status_code)}'

    def test_theme_setting(self, admin_client: APIClient):
        response = admin_client.patch(
            reverse(self.THEME_SETTING),
            data={
                'background': 'dark',
                'theme': 'green'
            },
            format='json'
        )

        log = UnifiedForumLog.objects.filter(content=self.format_content(
            '深色背景', '绿色', response.status_code
        ))

        assert log.exists()
        self.check_type_and_category(log[0])


class TestLocationLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_SYSTEM
    category = UnifiedForumLog.CATEGORY_OPERATION

    LOCATION_SETTING = 'setting-location'

    def format_content(self, city):
        return f'设置系统所在城市为: {city}'

    def test_location_setting(self, config_client: APIClient):
        config_client.post(
            reverse(self.LOCATION_SETTING),
            data={'city': '杭州'},
            format='json'
        )

        log = self.get_queryset().filter(content=self.format_content('杭州'))
        assert log.exists()
        self.check_type_and_category(log[0])


class TestSecutyCenterCleanLog(BaseLogTest):
    type = UnifiedForumLog.TYPE_SYSTEM
    category = UnifiedForumLog.CATEGORY_OPERATION

    SECURITY_CENTER = 'security-center-clean'

    def format_content(self, cycle):
        return f'设置安全中心统计数据清理时间为: {cycle}个月'

    def test_security_center_clean(self, config_client: APIClient):
        config_client.patch(
            reverse(self.SECURITY_CENTER),
            data={'security_center': 3},
            format='json'
        )

        log = self.get_queryset().filter(content=self.format_content('3'))
        assert log.exists()
        self.check_type_and_category(log[0])
