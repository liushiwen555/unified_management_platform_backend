import random
from datetime import timedelta, datetime
from copy import deepcopy

import pytest
from faker import Faker
from django.utils import timezone

from auditor.bolean_auditor.process_protocol import TodayExternalIP, PortRank, \
    ProtocolIPRank, IPSource, Processor, IPQueueProcess, PreProcess, AttackIPRank
from utils.unified_redis import cache, IPDuplicate
from statistic.tasks import AttackIPStatisticTask

fake = Faker()

fake1 = fake.ipv4()
fake2 = fake.ipv4()
fake3 = fake.ipv4()
fake4 = fake.ipv4()
fake5 = fake.ipv4()
fake6 = fake.ipv4()


@pytest.fixture(scope='function')
def data():
    data_7 = [
        {'src_ip': None, 'dst_ip': None, 'src_port': None, 'dst_port': None,
         'occurred_at': '2020-12-24T06:10:00'}
        for _ in range(20)]
    data_1 = [{'src_ip': fake1, 'dst_ip': '192.168.1.1', 'src_port': 22,
               'dst_port': 4443, 'occurred_at': '2020-12-24T06:10:00'}
              for _ in range(10)]
    data_2 = [{'src_ip': '10.0.1.1', 'dst_ip': fake2, 'src_port': 32,
               'dst_port': 6665, 'occurred_at': '2020-12-24T06:10:00'}
              for _ in range(8)]
    data_3 = [{'src_ip': fake3, 'dst_ip': '172.16.15.1', 'src_port': 11,
               'dst_port': 443, 'occurred_at': '2020-12-24T06:10:00'}
              for _ in range(6)]
    data_4 = [{'src_ip': '10.0.2.2', 'dst_ip': fake4, 'src_port': 2222,
               'dst_port': 2222, 'occurred_at': '2020-12-24T06:10:00'}
              for _ in range(4)]
    data_5 = [{'src_ip': fake5, 'dst_ip': '172.16.16.1', 'src_port': 42,
               'dst_port': 3333, 'occurred_at': '2020-12-24T06:10:00'}
              for _ in range(2)]
    data_6 = [
        {'src_ip': fake6, 'dst_ip': '10.4.4.4', 'src_port': 12, 'dst_port': 12,
         'occurred_at': '2020-12-24T06:10:00'}
        for _ in range(1)]
    data_8 = [
        {'src_ip': '2401:ba00:8:1::1', 'dst_ip': '2401:ba00:8:1::2',
         'src_port': None, 'dst_port': None,
         'occurred_at': '2020-12-24T06:10:00'}
    ]

    return data_1 + data_2 + data_3 + data_4 + data_5 + data_6 + data_7 + data_8


class TestTodayExternalIP:
    def test_external_ip(self, data):
        TodayExternalIP.clean()
        process = TodayExternalIP(timezone.now())

        for d in data:
            process.process(d)
        process.save()
        assert process.get_top_n() == [
            {'ip': fake1, 'count': 10},
            {'ip': fake2, 'count': 8},
            {'ip': fake3, 'count': 6},
            {'ip': fake4, 'count': 4},
            {'ip': fake5, 'count': 2},
        ]


class TestPortRank:
    def test_port_rank(self, data):
        PortRank.clean()
        process = PortRank(timezone.now())

        for d in data:
            process.process(d)
        process.save()

        src = [
            {'port': '22', 'count': 10},
            {'port': '32', 'count': 8},
            {'port': '11', 'count': 6},
            {'port': '2222', 'count': 4},
            {'port': '42', 'count': 2},
            {'port': '其他', 'count': 1}
        ]
        dst = [
            {'port': '4443', 'count': 10},
            {'port': '6665', 'count': 8},
            {'port': '443', 'count': 6},
            {'port': '2222', 'count': 4},
            {'port': '3333', 'count': 2},
            {'port': '其他', 'count': 1}
        ]
        assert process.get_top_n_src_port() == src
        assert process.get_top_n_dst_port() == dst
        assert process.get_top_n() == {
            'src_port': src,
            'dst_port': dst,
        }


@pytest.mark.django_db
class TestProtocolIPRank:
    """
    测试IP通讯排名，分为源IP和目的IP
    """

    def test_process(self, data):
        ProtocolIPRank.clean()
        process = ProtocolIPRank(timezone.now())
        for d in data:
            process.process(d)
        process.save()

        src = [
            {'ip': fake1, 'count': 10, 'percent': 100.0},
            {'ip': '10.0.1.1', 'count': 8, 'percent': 80.0},
            {'ip': fake3, 'count': 6, 'percent': 60.0},
            {'ip': '10.0.2.2', 'count': 4, 'percent': 40.0},
            {'ip': fake5, 'count': 2, 'percent': 20.0},
        ]
        assert process.get_top_n_src_ip() == src

        dst = [
            {'ip': '192.168.1.1', 'count': 10, 'percent': 100.0},
            {'ip': fake2, 'count': 8, 'percent': 80.0},
            {'ip': '172.16.15.1', 'count': 6, 'percent': 60.0},
            {'ip': fake4, 'count': 4, 'percent': 40.0},
            {'ip': '172.16.16.1', 'count': 2, 'percent': 20.0},
        ]
        assert process.get_top_n_dst_ip() == dst
        assert process.get_top_n() == {
            'src_ip': src, 'dst_ip': dst
        }


@pytest.mark.django_db
class TestProcess:
    def test_process_list(self, data):
        processor = Processor.process_list(timezone.now())
        processor_ = processor
        while processor_:
            processor_.clean()
            processor_ = processor_._next_processor
        for d in data:
            processor.process(d)
        processor.save()
        assert cache.keys(TodayExternalIP.key_pattern + '*') != []
        assert cache.keys(PortRank.src_total_key_pattern + '*') != []
        assert cache.keys(ProtocolIPRank.src_ip_pattern + '*') != []
        assert cache.keys(IPSource.city_key_pattern + '*') != []
        assert cache.keys(IPQueueProcess.foreign_key + '*') != []
        assert cache.keys(AttackIPRank.src_ip_pattern + '*') != []


foreign_data = [
    {'src_ip': '67.220.91.30', 'dst_ip': '192.168.2.2', 'country': '美国',
     'occurred_at': '2020-12-24T06:10:00'},
    {'src_ip': '133.242.187.207', 'dst_ip': '175.45.20.138', 'country': '日本',
     'occurred_at': '2020-12-24T06:10:00'},  # 日本
    {'src_ip': '212.219.142.207', 'dst_ip': '192.168.1.1', 'country': '英国',
     'occurred_at': '2020-12-24T06:10:00'},  # 英国
    {'src_ip': '176.192.102.130', 'dst_ip': '192.168.1.1', 'country': '俄罗斯',
     'occurred_at': '2020-12-24T06:10:00'},  # 俄罗斯
    {'src_ip': '92.103.174.236', 'dst_ip': '192.168.1.1', 'country': '法国',
     'occurred_at': '2020-12-24T06:10:00'},  # 法国
]

chinese_data = [
    {'src_ip': '175.45.20.138', 'dst_ip': '202.207.251.20',
     'occurred_at': '2020-12-24T06:10:00'},  # 香港->太原
    {'src_ip': '122.100.160.253', 'dst_ip': '123.138.162.112',
     'occurred_at': '2020-12-24T06:10:00'},  # 澳门->西安
    {'src_ip': '123.193.51.187', 'dst_ip': '192.168.1.1',
     'occurred_at': '2020-12-24T06:10:00'},  # 台北->北京
    {'src_ip': '192.168.1.1', 'dst_ip': '123.193.51.187',
     'occurred_at': '2020-12-24T06:10:00'},  # 北京->台北
    {'src_ip': '192.168.1.1', 'dst_ip': '10.0.1.1',
     'occurred_at': '2020-12-24T06:10:00'},  # 内网不记录
    {'src_ip': None, 'dst_ip': '192.168.1.1',
     'occurred_at': '2020-12-24T06:10:00'},
    {'src_ip': '123.222.222.222', 'dst_ip': None,
     'occurred_at': '2020-12-24T06:10:00'},
    {'src_ip': None, 'dst_ip': None, 'occurred_at': '2020-12-24T06:10:00'},
]

ipv6_data = [
    {'src_ip': '2401:ba00:8:1::1', 'dst_ip': '2401:ba00:8:1::1',
     'occurred_at': '2020-12-24T06:10:00'},
    {'src_ip': '2001:200:1c0:3601::80:1', 'dst_ip': 'fe80::50ee:cfff:fe4b:783a',
     'occurred_at': '2020-12-24T06:10:00'}
]


@pytest.mark.django_db
class TestIPSource:
    """
    IPSource模块做了很多工作，比如统计IP地图，威胁源地区，攻击次数，攻击源IP，境外访问个数
    """
    def create_processor(self):
        current = timezone.now()
        processor = PreProcess(current)
        processor.set_next(IPSource(current))
        return processor

    def test_ip_map_foreign(self):
        """
        国外IP流向
        """
        IPSource.clean()
        source = self.create_processor()
        data = foreign_data + ipv6_data
        for d in data:
            for _ in range(2):
                source.process(d)
        source.save()
        source = IPSource(timezone.now())
        result = source.get_city_data()
        for i, r in enumerate(result):
            assert r.src_c in ['美国', '日本', '英国', '俄罗斯', '法国']
            assert r.dst_c == '中国'
            assert r.count == 2

        source = IPSource(timezone.now())
        for d in foreign_data:
            source.process(d)
        source.save()
        result = source.get_city_data()
        for i, r in enumerate(result):
            assert r.src_c in ['美国', '日本', '英国', '俄罗斯', '法国']
            assert r.dst_c == '中国'
            assert r.count == 3

    def test_ip_map_chinese(self):
        """
        国内IP流向
        """
        IPSource.clean()
        source = self.create_processor()
        for d in chinese_data[:3]:
            for _ in range(5):
                source.process(d)
        source.save()
        source = IPSource(timezone.now())
        result = source.get_city_data()
        for i, r in enumerate(result):
            assert r.city in ['香港->太原', '澳门->西安', '台北->北京', '北京->台北']
            assert r.count == 5

    def test_external_ip(self):
        """
        外网IP数据量, 源或目的IP是外网的都统计，不去重
        :return:
        """
        IPDuplicate.create_external_ip(timezone.now()).force_clean()
        IPSource.clean()
        source = self.create_processor()
        data = foreign_data + chinese_data + ipv6_data
        for d in data:
            source.process(d)
        source.save()
        source = IPSource(timezone.now())
        assert source.get_attack_data()['external_ip'] == 16

    def test_attack_count(self):
        """
        攻击次数统计，源IP是外网IP的统计，不去重
        """
        IPDuplicate.create_external_ip(timezone.now()).force_clean()
        IPSource.clean()
        source = self.create_processor()
        data = foreign_data + chinese_data + ipv6_data
        for d in data:
            source.process(d)
        source.save()
        source = IPSource(timezone.now())
        assert source.get_attack_data()['count'] == 11

    def test_attack_src_ip(self):
        """
        今日攻击源IP个数，IP需要对今日已出现的IP去重
        """
        IPSource.clean()
        source = self.create_processor()
        data = foreign_data + foreign_data + chinese_data + chinese_data + ipv6_data
        for d in data:
            source.process(d)
        source.save()
        source = IPSource(timezone.now())
        assert source.get_attack_data()['src_ip'] == 11

    def test_attack_foreign(self):
        """
        今日境外访问IP个数，需要对今日已出现的ip去重
        """
        IPSource.clean()
        source = self.create_processor()
        data = foreign_data + foreign_data + chinese_data + chinese_data + ipv6_data
        for d in data:
            source.process(d)
        source.save()
        source = IPSource(timezone.now())
        assert source.get_attack_data()['foreign'] == 6

    def test_attack_history_src_ip(self):
        """
        累计的攻击源IP个数，需要对历史的IP去重
        """
        duplicate = IPDuplicate.create_duplicate_ip(timezone.now())
        duplicate.force_clean()
        for i in ['67.220.91.30', '133.242.187.207', '123.193.51.187']:
            duplicate.is_duplicate_ip(i)
        IPSource.clean()
        source = IPSource(timezone.now())
        data = foreign_data + foreign_data + chinese_data + chinese_data + ipv6_data
        for d in data:
            source.process(d)
        source.save()

        assert source.get_attack_data()['history_src_ip'] == 8

    def test_attack_history_foreign(self):
        """
        累计的境外IP个数，需要对历史的IP去重
        """
        duplicate = IPDuplicate.create_duplicate_ip(timezone.now())
        duplicate.force_clean()
        for i in ['67.220.91.30', '133.242.187.207', '123.193.51.187']:
            duplicate.is_duplicate_ip(i)
        IPSource.clean()
        source = IPSource(timezone.now())
        data = foreign_data + foreign_data + chinese_data + chinese_data + ipv6_data
        for d in data:
            source.process(d)
        source.save()

        assert source.get_attack_data()['history_foreign'] == 4

    def test_attack_ip_statistic_total(self):
        duplicate = IPDuplicate.create_duplicate_ip(timezone.now())
        duplicate.force_clean()
        for i in ['67.220.91.30', '133.242.187.207', '123.193.51.187']:
            duplicate.is_duplicate_ip(i)
        data = foreign_data + foreign_data + chinese_data + chinese_data + ipv6_data
        IPSource.clean()
        source = IPSource(timezone.now() - timedelta(days=1))
        for d in data:
            source.process(d)
        source.save()

        statistic = AttackIPStatisticTask.run(timezone.now())
        assert statistic.count == 5 + 5 + 4 + 4 + 2
        assert statistic.src_ip == 3 + 3 + 2
        assert statistic.foreign == 3 + 1
        assert statistic.external_ip == 6 + 6 + 7 + 7 + 3

    def test_get_country_top(self):
        """
        获取国家排名前5名的
        """
        data = foreign_data + foreign_data + chinese_data + ipv6_data
        IPSource.clean()
        source = IPSource(timezone.now())
        for d in data:
            source.process(d)
        source.save()

        country = source.get_country_top_n()

        assert sorted([i.country for i in country]) == \
               sorted(['中国', '美国', '日本', '英国', '俄罗斯'])


@pytest.mark.django_db
class TestIPQueueProcess:
    def create_proccessor(self):
        current = timezone.now()
        processor = PreProcess(current)
        processor.set_next(IPQueueProcess(current))
        return processor

    def test_external_ip(self):
        """
        每次执行，保留最近的5条外网IP数据
        """
        chinese_data_copy = deepcopy(ipv6_data) + deepcopy(chinese_data)
        for i, c in enumerate(chinese_data_copy):
            c['occurred_at'] = datetime(2020, 12, 24, 6, 40 - i).isoformat()
        IPQueueProcess.clean()
        process = self.create_proccessor()
        for c in chinese_data_copy:
            process.process(c)
        process.save()
        process = IPQueueProcess(timezone.now())
        result = process.get_external_ip()
        assert [r['ip'] for r in result] == [
            '2401:ba00:8:1::1', '2001:200:1c0:3601::80:1', '175.45.20.138',
            '122.100.160.253', '123.193.51.187']

        data_copy = deepcopy(chinese_data) + deepcopy(ipv6_data)
        for i, c in enumerate(data_copy):
            c['occurred_at'] = datetime(2020, 12, 24, 7, 40 - i).isoformat()
        process = self.create_proccessor()
        for c in data_copy:
            process.process(c)
        process.save()
        process = IPQueueProcess(timezone.now())
        result = process.get_external_ip()
        assert [r['ip'] for r in result] == [
            '175.45.20.138', '122.100.160.253', '123.193.51.187',
            '123.222.222.222', '2401:ba00:8:1::1',
        ]

    def test_foreign_ip(self):
        """
        每次执行保存最近的5条境外IP数据
        """
        data_copy = deepcopy(ipv6_data) + deepcopy(chinese_data) + deepcopy(
            foreign_data)

        for i, c in enumerate(data_copy):
            c['occurred_at'] = datetime(2020, 12, 24, 7, 50 - i).isoformat()
        IPQueueProcess.clean()
        process = self.create_proccessor()
        for c in data_copy:
            process.process(c)
        process.save()
        process = IPQueueProcess(timezone.now())
        result = process.get_foreign_ip()
        assert [r['ip'] for r in result] == [
            '123.222.222.222', '67.220.91.30', '133.242.187.207',
            '212.219.142.207', '176.192.102.130',
        ]

        data_copy = deepcopy(foreign_data) + deepcopy(ipv6_data) + deepcopy(
            chinese_data)
        for i, c in enumerate(data_copy):
            c['occurred_at'] = datetime(2020, 12, 24, 8, 50 - i).isoformat()
        process = self.create_proccessor()
        for c in data_copy:
            process.process(c)
        process.save()
        process = IPQueueProcess(timezone.now())
        result = process.get_foreign_ip()
        assert [r['ip'] for r in result] == [
            '67.220.91.30', '133.242.187.207',
            '212.219.142.207', '176.192.102.130', '92.103.174.236'
        ]


@pytest.mark.django_db
class TestAttackIPRank:
    def create_processor(self):
        current = timezone.now()
        processor = PreProcess(current)
        processor.set_next(AttackIPRank(current))
        return processor

    def test_external_ip_rank(self, data):
        AttackIPRank.clean()
        processor = self.create_processor()
        for d in data:
            processor.process(d)
        processor.save()
        attack = AttackIPRank(timezone.now())
        src = [
            {'ip': fake1, 'count': 10, 'percent': 100.0},
            {'ip': fake3, 'count': 6, 'percent': 60.0},
            {'ip': fake5, 'count': 2, 'percent': 20.0},
            {'ip': fake6, 'count': 1, 'percent': 10.0}
        ]
        assert attack.get_top_n_src_ip() == src
        dst = [
            {'ip': '192.168.1.1', 'count': 10, 'percent': 100.0},
            {'ip': '172.16.15.1', 'count': 6, 'percent': 60.0},
            {'ip': '172.16.16.1', 'count': 2, 'percent': 20.0},
            {'ip': '10.4.4.4', 'count': 1, 'percent': 10.0},
        ]
        assert attack.get_top_n_dst_ip() == dst
        assert attack.get_top_n() == {
            'src_ip': src, 'dst_ip': dst
        }
