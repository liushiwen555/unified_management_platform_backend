import time

import pytest
import faker

from unified_log.log_process import *
from base_app.models import Device
from base_app.factory_data import DeviceFactory
from base_app.serializers import DeviceRetrieveSerializer
from unified_log.unified_error import LogProcessError, LogPreProcessError
from unified_log.elastic.elastic_client import client
from unified_log.elastic.elastic_model import AuthLog
from unified_log.factory_data import LogProcessTemplateFactory
from unified_log.models import LogProcessRule, LogProcessTemplate, LOG_AUTH, LogStatistic
from utils.unified_redis import cache
from elasticsearch_dsl import Q
from statistic.tasks import DeviceLogCountTask

FACILITY = 'auth'
fake = faker.Faker()


@pytest.mark.django_db
class BaseTest:
    @pytest.fixture(scope='class')
    def log_rule(self) -> LogProcessRule:
        return LogProcessRule.objects.filter(log_type=LOG_AUTH).first()

    @pytest.fixture(scope='class')
    def log_template(self, log_rule) -> LogProcessTemplate:
        template = LogProcessTemplate.objects.first()
        setattr(template, FACILITY, log_rule)
        template.save()
        return template

    @pytest.fixture(scope='class')
    def device(self, log_template) -> Device:
        device_ = Device.objects.first()
        device_.log_template = log_template
        device_.save()
        return device_


@pytest.mark.django_db
class TestDeviceRuleCache(BaseTest):
    def test_set(self, device: Device, log_template: LogProcessTemplate,
                 log_rule: LogProcessRule):
        device_cache.set(
            device.ip,
            FACILITY,
            device_cache._to_dict(device, log_template, log_rule)
        )

        assert cache.hgetall(device_cache._key(device.ip, 'auth')) is not None

    def test_get(self, device: Device, log_template: LogProcessTemplate,
                 log_rule: LogProcessRule):
        cached_device = device_cache.get(device.ip, FACILITY)
        assert isinstance(cached_device, AbstractDevice)
        assert device.get_type_display() == cached_device.type
        assert cached_device.log_template == log_template.name
        assert isinstance(cached_device.log_rule, AbstractRule)
        assert log_rule.id == int(cached_device.log_rule.id)

    def test_get_expire(self, device: Device, log_template: LogProcessTemplate,
                        log_rule: LogProcessRule):
        cache.delete(device_cache._key(device.ip, FACILITY))
        cached_device = device_cache.get(device.ip, FACILITY)

        assert isinstance(cached_device, AbstractDevice)
        assert device.get_type_display() == cached_device.type
        assert cached_device.log_template == log_template.name
        assert isinstance(cached_device.log_rule, AbstractRule)
        assert log_rule.id == int(cached_device.log_rule.id)

    def test_clean(self):
        cache.set(device_cache.pattern + 'test', 1)
        device_cache.clean()
        assert cache.keys(device_cache.pattern + '*') == []


@pytest.mark.django_db
class TestLogProcess(BaseTest):
    logs = [
        '2020-10-14 10:05:27 ubuntu {} 4 6 systemd-logind[892]:  Removed session 11.',
        '2020-10-14 18:05:20 bolean {} 4 6 sshd[16224]:  pam_unix(sshd:session): session closed for user bolean',
        '2020-10-14 18:06:51 bolean {} 4 6 sshd[15813]:  Received disconnect from 192.168.0.40 port 53566:11: disconnected by user'
    ]

    @pytest.fixture(scope='class')
    def template(self):
        log = AuthLog._index.as_template(AuthLog.index_name(),
                                         pattern=AuthLog.index_pattern(),
                                         order=0)
        log.save()

    @pytest.mark.parametrize('log', logs)
    def test_get_ip_facility(self, device: Device, log: str):
        log = log.format(device.ip)
        process = LogProcess(log)
        ip, facility, log_time = process.get_ip_facility_log_time()

        assert ip == device.ip
        assert facility == FACILITY

    def test_get_ip_facility_illegal_log(self):
        log = 'asdjojdo1j2odjo12do21'
        with pytest.raises(LogPreProcessError):
            LogProcess(log)

        log = '2020-10-14 10:05:27 ubuntu 127.0.0.1 50 6 systemd-logind[892]:  Removed session 11.'
        with pytest.raises(LogPreProcessError):
            LogProcess(log)

    @pytest.mark.parametrize('log', logs)
    def test_device_with_log_status(self, log):
        device = DeviceFactory.create(log_status=False)
        log = log.format(device.ip)
        with pytest.raises(LogPreProcessError):
            LogProcess(log)

    @pytest.mark.parametrize('log', logs)
    def test_get_device_rule_full(self, device: Device, log: str,
                                  log_rule: LogProcessRule, ):
        log = log.format(device.ip)
        process = LogProcess(log)
        d = process.get_device()
        rule = d.log_rule
        assert d.name == device.name
        assert rule.id == log_rule.id

    @pytest.mark.parametrize('log', logs)
    def test_get_device_rule_no_device(self, log: str):
        """
        测试根据日志找不到对应资产的情况，此情况下不保存原始日志
        """
        log = log.format('0.0.0.0')
        with pytest.raises(LogPreProcessError):
            LogProcess(log)

    def test_get_device_rule_no_template(self):
        """
        测试根据日志和资产找不到模板的情况，此情况下需要保存原始日志
        :param log:
        :return:
        """
        device = DeviceFactory.create(log_template=None)

        log = '2020-10-14 10:05:30 ubuntu {} 4 6 systemd-logind[892]:  Removed session 11.'.format(device.ip)
        process = LogProcess(log)
        try:
            process.process()
            assert False
        except LogProcessError as e:
            assert True
            process.save()
            print(e)
            time.sleep(1)
            assert BaseDocument.search().filter(
                'match', status=False).filter(
                'match', ip=device.ip).count() == 1

    @pytest.mark.parametrize('log', logs)
    def test_get_device_rule_no_rule(self, log: str):
        """
        测试日志解析出了资产和对应模板，但是没有配置规则导致解析失败，需要存原始日志
        """
        template = LogProcessTemplateFactory()
        setattr(template, FACILITY, None)
        template.save()
        device = DeviceFactory.create(log_template=template)

        log = log.format(device.ip)
        with pytest.raises(LogProcessError):
            log = LogProcess(log)
            log.process()
        log.save()
        time.sleep(1)
        assert BaseDocument.search().filter(
            'match', status=False).filter(
            'match', ip=device.ip).count() == 1

    @pytest.mark.parametrize('log, src_ip, src_port',
                             [[logs[0], None, None],
                              [logs[1], None, None],
                              [logs[2], '192.168.0.40', '53566']])
    def test_process(self, device: Device, log: str, src_ip: str,
                     src_port: str):
        log = log.format(device.ip)
        process = LogProcess(log)
        result = process.process()

        assert result['src_ip'] == src_ip
        assert result['src_port'] == src_port

    @pytest.mark.parametrize('log, src_ip, src_port',
                             [(logs[2], '192.168.0.40', 53566)])
    def test_save(self, device: Device, log: str, src_ip: str, src_port: str,
                  template):
        current = datetime.utcnow()
        log = log.format(device.ip)
        process = LogProcess(log)
        process.process()
        process.save()

        client.flush_index(process.log.index_pattern())

        log = AuthLog.search().query('bool', filter=[
            Q('match', src_ip=src_ip), Q('term', src_port=src_port),
            Q('range', timestamp={'gt': current})
        ])
        assert log is not None

    @pytest.mark.parametrize('log, src_ip, src_port',
                             [(logs[2], '192.168.0.40', 53566)])
    def test_save_directly(self, device: Device, log: str, src_ip: str,
                           src_port: str, template):
        current = datetime.utcnow()
        log = log.format(device.ip)
        process = LogProcess(log)
        process.save()

        client.flush_index(process.log.index_pattern())

        log = AuthLog.search().query('bool', filter=[
            Q('match', src_ip=src_ip), Q('term', src_port=src_port),
            Q('range', timestamp={'gt': current})
        ])
        assert log is not None

    @pytest.mark.parametrize('log, src_ip, src_port',
                             [(logs[2], '192.168.0.40', 53566)])
    def test_without_document(self, device: Device, log: str, src_ip: str,
                              src_port: str):
        """
        没有查到对应的日志模板
        """
        log = log.format(device.ip)
        process = LogProcess(log)
        process.device.log_rule.log_type = -2
        with pytest.raises(LogProcessError):
            process.process()
        process.save()
        client.flush_index('test*')
        time.sleep(0.5)
        assert BaseDocument.search().filter(
            'match', status=False).filter(
            'match', ip=device.ip).count() == 1

    def test_failed_log_process(self, device: Device):
        """
        基础信息都获取到，但是日志主题内容解析失败后会存储原始日志
        """
        log = '2020-10-14 10:05:20 ubuntu {} 4 6 1231231d dd'.format(device.ip)
        process = LogProcess(log)

        with pytest.raises(LogProcessError):
            process.process()
        process.save()
        time.sleep(1)
        assert BaseDocument.search().filter(
            'match', status=False).filter(
            'match', log_time=datetime(2020, 10, 14, 10, 5, 20)).count() == 1

    def test_total_log_device(self, log_template):
        """
        测试统计累计日志
        """
        device = DeviceFactory.create_normal(log_status=True)
        device = Device.objects.get(id=device.id)
        device.log_template = log_template
        device.save()
        log = self.logs[0].format(device.ip)

        log_process = LogProcess(log)
        log_process.save()
        time.sleep(1)
        DeviceLogCountTask.run(timezone.now())
        log_statistic = LogStatistic.objects.filter(device_id=device.id).first()
        assert log_statistic.total == 1

        for _ in range(20):
            log_process = LogProcess(log)
            log_process.save()
        client.flush_index('test-*')
        time.sleep(1)
        DeviceLogCountTask.run(timezone.now())
        log_statistic = LogStatistic.objects.filter(device_id=device.id).first()
        assert log_statistic.total == 21
        serializer = DeviceRetrieveSerializer(device)
        assert serializer.data['today_log'] == 21

