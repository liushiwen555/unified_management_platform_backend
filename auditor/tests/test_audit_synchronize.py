from copy import deepcopy
from typing import Dict, List, Union

import pytest
from django.db.models import Count
from django.utils import timezone

from auditor.bolean_auditor import AuditorSynchronize
from auditor.bolean_auditor.process_protocol import AlertCategoryDistribution, \
    IncrementDistributionProcess
from auditor.bolean_auditor.synchronize import DeviceCache, \
    AuditorSynchronizeLog
from auditor.models import AuditorBlackList
from auditor.tests.data import alert_data
from base_app.factory_data import DeviceFactory
from base_app.models import Device
from log.factory_data import DeviceAllAlertFactory
from log.models import IncrementDistribution, AlertDistribution, DeviceAllAlert


@pytest.fixture(scope='class')
def cache() -> DeviceCache:
    return DeviceCache(10)


@pytest.mark.django_db
class TestDeviceCache:
    def test_get_none_ip(self, cache: DeviceCache):
        assert cache.get(None) is None

    def test_get_ip_not_exists(self, cache: DeviceCache):
        assert cache.get('123.1.1.111') is None
        assert cache.is_banned_ip('123.1.1.111')

    def test_get_ip(self, cache: DeviceCache):
        device = DeviceFactory.create_normal()

        assert cache.get(device.ip) == device.id
        assert not cache.is_banned_ip(device.ip)

        assert cache.get(device.ip) == device.id

    def test_get_more_devices(self, cache: DeviceCache):
        devices = DeviceFactory.create_batch_normal(20)
        for d in devices:
            assert cache.get(d.ip) == d.id
        assert cache.count == 10


data = {
    'max_id': 2905,
    'log_list': [
        {'id': 201, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:41:39.928414+08:00', 'count': 183,
         'other_info': {'id': 115, 'sid': 100133, 'event-id': 1, 'book_mark': [
             '/var/log/suricata/unified2.alert.1608027449', 60],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(CPU Stop)'}},
        {'id': 202, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:41:39.929996+08:00', 'count': 184,
         'other_info': {'id': 116, 'sid': 100134, 'event-id': 2, 'book_mark': [
             '/var/log/suricata/unified2.alert.1608027449', 120],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(Crash CPU)'}},
        {'id': 203, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:41:40.875062+08:00', 'count': 1947,
         'other_info': {'id': 115, 'sid': 100133, 'event-id': 368,
                        'book_mark': [
                            '/var/log/suricata/unified2.alert.1608027449',
                            22080],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(CPU Stop)'}},
        {'id': 204, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '133.242.187.207', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:41:40.880054+08:00', 'count': 1946,
         'other_info': {'id': 116, 'sid': 100134, 'event-id': 370,
                        'book_mark': [
                            '/var/log/suricata/unified2.alert.1608027449',
                            22200],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(Crash CPU)'}},
        {'id': 213, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:41:50.927508+08:00', 'count': 1945,
         'other_info': {'id': 115, 'sid': 100133, 'event-id': 4261,
                        'book_mark': [
                            '/var/log/suricata/unified2.alert.1608027449',
                            255660],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(CPU Stop)'}},
        {'id': 214, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:41:50.929044+08:00', 'count': 1944,
         'other_info': {'id': 116, 'sid': 100134, 'event-id': 4262,
                        'book_mark': [
                            '/var/log/suricata/unified2.alert.1608027449',
                            255720],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(Crash CPU)'}},
        {'id': 223, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:42:00.967660+08:00', 'count': 1945,
         'other_info': {'id': 116, 'sid': 100134, 'event-id': 8150,
                        'book_mark': [
                            '/var/log/suricata/unified2.alert.1608027449',
                            489000],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(Crash CPU)'}},
        {'id': 224, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:42:00.972933+08:00', 'count': 1944,
         'other_info': {'id': 115, 'sid': 100133, 'event-id': 8152,
                        'book_mark': [
                            '/var/log/suricata/unified2.alert.1608027449',
                            489120],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(CPU Stop)'}},
        {'id': 233, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:42:11.007210+08:00', 'count': 1943,
         'other_info': {'id': 116, 'sid': 100134, 'event-id': 12039,
                        'book_mark': [
                            '/var/log/suricata/unified2.alert.1608027449',
                            722340],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(Crash CPU)'}},
        {'id': 234, 'is_read': False, 'read_at': None, 'memo': None,
         'category': 1, 'level': 3, 'src_mac': None,
         'src_ip': '192.168.111.186', 'src_port': 58810, 'dst_mac': None,
         'dst_ip': '192.168.111.45', 'dst_port': 44818, 'origin_mac': None,
         'conflict_mac': None, 'protocol': 'TCP', 'illegal_ip': None,
         'last_at': '2020-12-16T10:42:11.011803+08:00', 'count': 1942,
         'other_info': {'id': 115, 'sid': 100133, 'event-id': 12040,
                        'book_mark': [
                            '/var/log/suricata/unified2.alert.1608027449',
                            722400],
                        'blacklist_name': '罗克韦尔自动化ControlLogix 拒绝服务(CPU Stop)'}}]
}


@pytest.mark.django_db
class TestSynchronize:
    @pytest.fixture(scope='function')
    def auditor(self) -> Device:
        device = DeviceFactory.create_normal(category=Device.CATEGORY_Security,
                                             type=Device.AUDITOR)
        return Device.objects.get(id=device.id)

    def test_save(self, auditor):
        sync = AuditorSynchronize(auditor, timezone.now())
        sync.save(data)

        assert DeviceAllAlert.objects.filter(src_country__exact='日本').exists()
        assert DeviceAllAlert.objects.filter(src_country__exact='中国').exists()


log_data = {
    'max_id': 109,
    'log_list': [{'id': 39, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 8, 'user': None, 'ip': None,
                  'content': 'BoleanGuard工控安全审计平台于2020-12-10 03:00:00自动删除超过保存时限的事件审计记录成功',
                  'occurred_at': '2020-12-10T03:00:00.036912+08:00'},
                 {'id': 40, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 8, 'user': None, 'ip': None,
                  'content': 'BoleanGuard工控安全审计平台于2020-12-10 04:00:00自动删除超过保存时限的日志审计记录成功',
                  'occurred_at': '2020-12-10T04:00:00.036864+08:00'},
                 {'id': 41, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 3, 'user': 'test', 'ip': '10.0.171.149',
                  'content': '工程师test于2020-12-10 09:30:13未进行操作达1014.0分钟，超时自动登出审计平台',
                  'occurred_at': '2020-12-10T09:30:13.579724+08:00'},
                 {'id': 42, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 3, 'user': 'test', 'ip': '10.0.171.149',
                  'content': '工程师test于2020-12-10 09:30:13未进行操作达1014.0分钟，超时自动登出审计平台',
                  'occurred_at': '2020-12-10T09:30:13.579788+08:00'},
                 {'id': 43, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 3, 'user': 'test', 'ip': '10.0.171.149',
                  'content': '工程师test于2020-12-10 09:30:13未进行操作达1014.0分钟，超时自动登出审计平台',
                  'occurred_at': '2020-12-10T09:30:13.579761+08:00'},
                 {'id': 44, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 3, 'user': 'test', 'ip': '10.0.171.149',
                  'content': 'test于2020-12-10 09:30:23登录审计平台成功',
                  'occurred_at': '2020-12-10T09:30:23.514405+08:00'},
                 {'id': 45, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 3, 'user': 'test', 'ip': '10.0.174.194',
                  'content': 'test于2020-12-10 10:33:15登录审计平台成功',
                  'occurred_at': '2020-12-10T10:33:15.906978+08:00'},
                 {'id': 46, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 3, 'user': 'test555', 'ip': '10.0.182.201',
                  'content': 'test555于2020-12-10 17:10:49登录审计平台成功',
                  'occurred_at': '2020-12-10T17:10:49.088108+08:00'},
                 {'id': 47, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 3, 'user': 'test', 'ip': '10.0.171.149',
                  'content': '工程师test于2020-12-10 17:41:25未进行操作达487.0分钟，超时自动登出审计平台',
                  'occurred_at': '2020-12-10T17:41:25.001396+08:00'},
                 {'id': 48, 'is_read': False, 'read_at': None, 'memo': None,
                  'category': 3, 'user': 'test', 'ip': '10.0.171.149',
                  'content': 'test于2020-12-10 17:41:33登录审计平台成功',
                  'occurred_at': '2020-12-10T17:41:33.296165+08:00'}]
}


@pytest.mark.django_db
class TestSynchronizeLog:
    @pytest.fixture(scope='function')
    def auditor(self) -> Device:
        device = DeviceFactory.create_normal(category=Device.CATEGORY_Security,
                                             type=Device.AUDITOR)
        return Device.objects.get(id=device.id)

    def test_save(self, auditor):
        sync = AuditorSynchronizeLog(auditor)
        sync.save(log_data)


@pytest.fixture(scope='class')
def auditor() -> Device:
    return Device.objects.filter(type=Device.AUDITOR,
                                 register_status=Device.REGISTERED).first()


@pytest.fixture(scope='class')
def alert_data_list() -> Dict[str, Union[List, str]]:
    alert = alert_data['log_list'][0]
    black_list = AuditorBlackList.objects.distinct('alert_category').values(
        'alert_category', 'sid').order_by('alert_category')
    res = []
    current = timezone.now()
    for b in black_list:
        for _ in range(b['alert_category'] * 5):
            a = deepcopy(alert)
            a['other_info']['sid'] = b['sid']
            a['last_at'] = current
            res.append(a)
    return {'log_list': res, 'max_id': 12345}


@pytest.mark.django_db
class TestAlertTrend:
    def test_save_alert(self, auditor: Device, alert_data_list):
        sync = AuditorSynchronize(auditor, timezone.now())
        sync.save(alert_data_list)

        device = Device.objects.get(id=auditor.id)
        assert device.audit_sec_alert_max_id == alert_data_list['max_id']

    def test_alert_distribution(self, auditor):
        """
        测试安全威胁分布，初次存储，会查询所有的安全威胁，后续同步只会同步上次之后的增量
        :return:
        """
        DeviceAllAlertFactory.create_batch(50)
        sync = AuditorSynchronize(auditor, timezone.now())
        # 初次同步，统计所有的安全威胁分布
        sync.save({'log_list': [], 'max_id': 1234})
        distribution = AlertDistribution.objects.first()
        result = DeviceAllAlert.objects.values('category').annotate(
            count=Count('id')).order_by('category')
        result = {i['category']: i['count'] for i in result}
        assert distribution.scan == result.get(DeviceAllAlert.CATEGORY_SCAN, 0)
        assert distribution.flaw == result.get(DeviceAllAlert.CATEGORY_FLAW, 0)
        assert distribution.apt == result.get(DeviceAllAlert.CATEGORY_APT, 0)
        assert distribution.other == result.get(DeviceAllAlert.CATEGORY_OTHER,
                                                0)

        # 后续的同步，只统计增量，加到原来的数据上
        data = alert_data_list()
        sync = AuditorSynchronize(auditor, timezone.now())
        sync.save(data)
        distribution = AlertDistribution.objects.first()
        assert distribution.scan == result.get(DeviceAllAlert.CATEGORY_SCAN,
                                               0) + DeviceAllAlert.CATEGORY_SCAN * 5
        assert distribution.flaw == result.get(DeviceAllAlert.CATEGORY_FLAW,
                                               0) + DeviceAllAlert.CATEGORY_FLAW * 5
        assert distribution.apt == result.get(DeviceAllAlert.CATEGORY_APT,
                                              0) + DeviceAllAlert.CATEGORY_APT * 5
        assert distribution.other == result.get(DeviceAllAlert.CATEGORY_OTHER,
                                                0) + DeviceAllAlert.CATEGORY_OTHER * 5

    def test_alert_trend(self, auditor, alert_data_list):
        DeviceAllAlertFactory.create_batch(20)
        sync = AuditorSynchronize(auditor, timezone.now())
        sync.save(alert_data_list)

        trend = IncrementDistribution.objects.first()
        assert trend is not None
        assert trend.scan == DeviceAllAlert.CATEGORY_SCAN * 5
        assert trend.flaw == DeviceAllAlert.CATEGORY_FLAW * 5
        assert trend.apt == DeviceAllAlert.CATEGORY_APT * 5
        assert trend.other == DeviceAllAlert.CATEGORY_OTHER * 5

    def test_device_cache(self, auditor):
        """
        每次同步的时候，为了减少数据库查询，将资产存入缓存，应为考虑到资产IP的变更，所以
        同步之后，缓存要抛弃，重新同步的时候，重新生成缓存
        """
        device = DeviceFactory.create_normal(ip='126.6.6.6')
        a = deepcopy(alert_data)
        a['log_list'][0]['dst_ip'] = device.ip
        sync = AuditorSynchronize(auditor, timezone.now())
        sync.save(a)
        assert DeviceAllAlert.objects.filter(device__id=device.id).exists()

        Device.objects.filter(id=device.id).delete()
        device = DeviceFactory.create_normal(ip='126.6.6.6')
        sync = AuditorSynchronize(auditor, timezone.now())
        sync.save(a)
        assert DeviceAllAlert.objects.filter(device__id=device.id).exists()

        a['log_list'][0]['dst_ip'] = '223.223.223.223'
        sync = AuditorSynchronize(auditor, timezone.now())
        sync.save(a)
        assert DeviceAllAlert.objects.order_by('-id').first().device is None


@pytest.mark.django_db
class TestAlertCategoryDistribution:
    def test_save(self):
        """
        存储威胁分布总量
        """
        current = timezone.now()
        process = AlertCategoryDistribution(current)
        process.save()
        apt = DeviceAllAlert.objects.filter(
            category=DeviceAllAlert.CATEGORY_APT).count()
        d = AlertDistribution.objects.first()
        assert d.update_time == current
        DeviceAllAlertFactory.create_batch(10,
                                           category=DeviceAllAlert.CATEGORY_APT)
        current = timezone.now()
        process = AlertCategoryDistribution(current)
        process.save()
        d = AlertDistribution.objects.first()
        assert d.update_time == current
        assert d.apt == 10 + apt


@pytest.mark.django_db
class TestIncrementDistribution:
    def test_save(self):
        """
        存储每次同步的威胁分布增量
        """
        current = timezone.now()
        process = IncrementDistributionProcess(current)

        black_list = AuditorBlackList.objects.distinct('alert_category').values(
            'alert_category', 'sid').order_by('alert_category')
        for b in black_list:
            for _ in range(10):
                a = {'category': b['alert_category']}
                process.process(a)
        process.save()

        distribution = IncrementDistribution.objects.first()
        assert distribution.scan == 10
        assert distribution.flaw == 10
        assert distribution.apt == 10
        assert distribution.other == 10
