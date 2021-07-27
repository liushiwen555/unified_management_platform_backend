import random

import pytest
from django.utils import timezone
from faker import Faker
from django.db import transaction
from django.db.utils import IntegrityError

from unified_log.elastic.elastic_client import client
from unified_log.elastic.elastic_model import template_register, BaseDocument, \
    get_all_fields
from unified_log.models import *
from utils.constants import SYSLOG_FACILITY
from unified_log.factory_data import LogProcessRuleFactory, \
    LogProcessTemplateFactory
from utils.counter import LocalFactory

fake = Faker('zh_CN')

PATTERN = r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
r'(?P<hostname>.*?) (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
r'(?P<facility>\d{1,2}) (?P<level>\d{1,2}).*?: '
r'(.*?(from (?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (?P<src_port>\d+)).*?'
r'|.*?)'


@pytest.mark.django_db
class TestLogProcessRule:
    def test_save_basic(self):
        rule = LogProcessRule(
            name=fake.text(max_nb_chars=10),
            category=random.choice(CATEGORY_CHOICE)[0],
            type=random.choice(DEV_TEMP_TYPE_CHOICES)[0],
            pattern=PATTERN,
            log_type=random.choice(LOG_TYPE_CHOICES)[0],
        )
        rule.save()
        print(rule)

        assert rule.id is not None

    def test_save_full(self):
        rule = LogProcessRule(
            name=fake.text(max_nb_chars=10),
            category=random.choice(CATEGORY_CHOICE)[0],
            type=random.choice(DEV_TEMP_TYPE_CHOICES)[0],
            pattern=PATTERN,
            log_type=random.choice(LOG_TYPE_CHOICES)[0],
            brand=fake.text(max_nb_chars=10),
            hardware=fake.text(max_nb_chars=10),
            example=fake.text(max_nb_chars=100),
            mark=fake.text(max_nb_chars=10),
        )
        rule.save()

        assert rule.id is not None

    def test_template_count(self):
        rule: LogProcessRule = LogProcessRuleFactory()
        LogProcessTemplateFactory.create(
            kern=rule, auth=rule, local0=rule
        )
        LogProcessTemplateFactory.create(
            lpr=rule, local1=rule
        )

        assert rule.template_count() == 2

    def test_duplicate_name(self):
        """
        同个category和type下，name不能重复
        """
        LogProcessRuleFactory.create(name='123123', category=1, type=1)

        with pytest.raises(IntegrityError):
            with transaction.atomic():
                LogProcessRuleFactory.create(name='123123', category=1, type=1)
        rule = LogProcessRuleFactory.create(name='123123', category=1, type=2)
        rule.save()

        assert rule.id is not None


@pytest.mark.django_db
class TestLogProcessTemplate:
    @pytest.fixture(scope='function')
    def rule(self) -> LogProcessRule:
        rule = LogProcessRule(
            name=fake.text(max_nb_chars=10),
            category=random.choice(CATEGORY_CHOICE)[0],
            type=random.choice(DEV_TEMP_TYPE_CHOICES)[0],
            pattern=PATTERN,
            log_type=random.choice(LOG_TYPE_CHOICES)[0],
        )
        rule.save()
        return rule

    def test_duplicate_name(self):
        """
        同个category和type下，name不能重复
        """
        LogProcessTemplateFactory.create(name='123123', category=1, type=1)

        with pytest.raises(IntegrityError):
            with transaction.atomic():
                LogProcessTemplateFactory.create(name='123123', category=1, type=1)
        rule = LogProcessTemplateFactory.create(name='123123', category=1, type=2)
        rule.save()

        assert rule.id is not None

    def test_save_without_rule(self):
        template = LogProcessTemplate(
            name=fake.text(max_nb_chars=10),
            category=random.choice(CATEGORY_CHOICE)[0],
            type=random.choice(DEV_TEMP_TYPE_CHOICES)[0],
        )

        template.save()
        print(template)

        assert template.id is not None

    def test_save_with_rule(self, rule: LogProcessRule):

        template = LogProcessTemplate(
            name=fake.text(max_nb_chars=10),
            category=random.choice(CATEGORY_CHOICE)[0],
            type=random.choice(DEV_TEMP_TYPE_CHOICES)[0],
            local0=rule,
        )

        template.save()

        assert template.id is not None
        assert rule.local0_temp is not None

    def test_save_with_all_rule(self, rule: LogProcessRule):
        template = LogProcessTemplate(
            name=fake.text(max_nb_chars=10),
            category=random.choice(CATEGORY_CHOICE)[0],
            type=random.choice(DEV_TEMP_TYPE_CHOICES)[0],
        )
        for i in SYSLOG_FACILITY.values():
            setattr(template, i, rule)

        template.save()

        for i in SYSLOG_FACILITY.values():
            assert getattr(rule, i + '_temp') is not None


class TestBaseDocument:
    index = BaseDocument

    expected_properties = {
        'src_ip': {'type': 'ip'},
        'dst_ip': {'type': 'ip'},
        'src_port': {'type': 'integer'},
        'dst_port': {'type': 'integer'},
        'dev_name': {'type': 'keyword'},
        'ip': {'type': 'ip'},
        'dev_category': {'type': 'keyword'},
        'dev_type': {'type': 'keyword'},
        'log_time': {'type': 'date'},
        'content': {'type': 'text'},
        'timestamp': {'type': 'date'},
        'status': {'type': 'boolean'},
        'dev_id': {'type': 'integer'},
        'id': {'type': 'keyword'},
    }

    def test_create_document(self):
        """
        测试创建document的时候，只有定义的字段，没有定义的字段不会传进去
        """
        document = self.index(
            ip=fake.ipv4(),
            src_ip=fake.ipv4(),
            dst_ip=fake.ipv4(),
            src_port=random.randint(1, 500),
            dst_port=random.randint(1, 500),
            src_mac=fake.mac_address(),
            dst_mac=fake.mac_address(),
            device_id=random.randint(1, 599),
            device_name=fake.text(),
            audit_logtype=random.randint(1, 100),
            audit_pri=random.randint(1, 100),
            mod=fake.text(),
            audit_msg=fake.text(),
            dev_id=62,
            dev_name=fake.text(max_nb_chars=20),
            dev_type=random.choice(DEV_TEMP_TYPE_CHOICES)[1],
            dev_category=random.choice(CATEGORY_CHOICE)[1],
            log_time=fake.date_time(),
            content=fake.text(),
            in_network=fake.ipv6(),
            out_network=fake.ipv6(),
            protocol=fake.text(max_nb_chars=10),
            status=False,
            audit_date='2020/10/10 10:10:10',
            nginx_date='2020/10/10 10:10:10',
            remote_user=fake.text(),
            request=fake.text(),
            status_code=random.randint(1, 100),
            body_bytes_sent=random.randint(1, 19),
            http_referer=fake.text(),
            http_user_agent=fake.text(),
            upstream=fake.text(),
            host=fake.text(),
            vpn_name=fake.text(),
            user=fake.first_name(),
            auth_method=fake.text(),
            command=fake.text(),
            sql=fake.text(),
            error=fake.text(),
            reason=fake.text(),
            requested_ip=fake.text(),
            DHCP=fake.text(),
            function=fake.text(max_nb_chars=20),
            source=fake.text(max_nb_chars=20),
            id=LocalFactory.get_count().add(1),
        )

        self.compare_fields(document.to_dict().keys())

    def compare_fields(self, keys):
        target = list(get_all_fields(self.index))
        target.sort()
        keys = list(keys)
        keys.sort()
        assert keys == target

    def create_mappings(self):
        template_name = 'test-' + self.index.Index.name
        log = self.index._index.as_template(template_name,
                                            pattern=template_name + '*',
                                            order=0)
        log.save()

        log_template = client.get_template(template_name)

        assert log_template.get(template_name) is not None
        template = log_template[template_name]
        assert template['order'] == 0
        assert template_name + '*' in template['index_patterns']

        return template


class TestAuthLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_AUTH)

    def test_mappings(self):
        template = self.create_mappings()

        assert template['mappings']['properties'] == self.expected_properties

    def test_to_dict(self):
        log = self.index(
            ip=fake.ipv4(),
            src_ip=fake.ipv4(),
            src_port=random.randint(1, 500),
            dev_name=fake.text(max_nb_chars=20),
            dev_type=random.choice(DEV_TEMP_TYPE_CHOICES)[1],
            dev_category=random.choice(CATEGORY_CHOICE)[1],
            log_time=fake.date_time(),
            content=fake.text(),
        )
        log.save()

        assert log.to_dict(True)['_index'] == \
               timezone.localtime().strftime(f'{log.index_name()}-%Y%m%d')
        assert log is not None


class TestKernLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_KERNEL)

    def test_mappings(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        expected_properties.update({
            'in_network': {'type': 'keyword'},
            'out_network': {'type': 'keyword'},
            'src_mac': {'type': 'keyword'},
            'protocol': {'type': 'keyword'},
        })
        assert template['mappings']['properties'] == expected_properties


class TestDaemonLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_DAEMON)

    def test_mappings(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        expected_properties.update({
            'protocol': {'type': 'keyword'},
        })
        assert template['mappings']['properties'] == expected_properties


class TestCronLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_CRON)

    def test_mappings(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        assert template['mappings']['properties'] == expected_properties


class TestAuditLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_AUDIT_ALARM)

    def test_mappings(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        expected_properties.update({
            'src_mac': {'type': 'keyword'},
            'dst_mac': {'type': 'keyword'},
            'device_id': {'type': 'integer'},
            'device_name': {'type': 'keyword'},
            'audit_date': {'type': 'date'},
            'audit_pri': {'type': 'integer'},
            'audit_logtype': {'type': 'integer'},
            'mod': {'type': 'keyword'},
            'protocol': {'type': 'keyword'},
            'audit_msg': {'type': 'text', 'analyzer': 'ik_max_word',
                          'search_analyzer': 'ik_smart'}
        })
        assert template['mappings']['properties'] == expected_properties


class TestNginxLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_NGINX)

    def test_mappings(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        expected_properties.update({
            'remote_user': {'type': 'keyword'},
            'nginx_date': {'type': 'date'},
            'request': {'type': 'text'},
            'http_referer': {'type': 'text'},
            'http_user_agent': {'type': 'text'},
            'upstream': {'type': 'text'},
            'host': {'type': 'text'},
            'status_code': {'type': 'integer'},
            'body_bytes_sent': {'type': 'integer'},
        })

        assert template['mappings']['properties'] == expected_properties


class TestMailLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_MAIL)

    def test_mappings(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        assert template['mappings']['properties'] == expected_properties


class TestFTPLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_FTP)

    def test_mappings(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        assert template['mappings']['properties'] == expected_properties


class TestHuaWeiSwitchLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_SWITCH_HUAWEI)

    def test_create_document(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        expected_properties.update({
            'device_name': {'type': 'keyword'},
            'vpn_name': {'type': 'keyword'},
            'user': {'type': 'keyword'},
            'auth_method': {'type': 'keyword'},
            'command': {'type': 'text'}
        })
        assert template['mappings']['properties'] == expected_properties


class TestPostgresLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_DATABASE_POSTGRESQL)

    def test_create_document(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        expected_properties.update({
            'sql': {'type': 'text'},
            'error': {'type': 'text'},
        })

        assert template['mappings']['properties'] == expected_properties


class TestAsusRouterLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_ROUTER_ASUS)

    def test_create_document(self):
        template = self.create_mappings()

        expected_properties = self.expected_properties.copy()
        expected_properties.update({
            'device_name': {'type': 'keyword'},
            'src_mac': {'type': 'keyword'},
            'dst_mac': {'type': 'keyword'},
            'status_code': {'type': 'integer'},
            'in_network': {'type': 'keyword'},
            'reason': {'type': 'text'},
            'requested_ip': {'type': 'ip'},
            'DHCP': {'type': 'keyword'},
            'function': {'type': 'text'},
            'source': {'type': 'text'},
        })

        assert template['mappings']['properties'] == expected_properties


class TestWindowsLog(TestBaseDocument):
    index = template_register.get_index_class(LOG_WINDOWS)

    def test_create_document(self):
        template = self.create_mappings()
        expected_properties = self.expected_properties.copy()
        expected_properties.update({
            'application': {'type': 'text'},
            'function': {'type': 'text'},
            'source': {'type': 'text'},
            'sid': {'type': 'keyword'}
        })

        assert template['mappings']['properties'] == expected_properties
