import time
import random
from datetime import datetime

import pytest
from faker import Faker

from unified_log.elastic.elastic_client import client
from unified_log.elastic.elastic_model import AuthLog
from utils.counter import LocalFactory

fake = Faker()


class TestElasticClient:
    @pytest.fixture(scope='function')
    def logs(self):
        counter = LocalFactory.get_count(key='test')
        client.create_template(
            'test-log-search-after',
            {
                'mappings':
                    {'properties':
                        {
                            'ip': {'type': 'ip'},
                            'timestamp': {'type': 'date'},
                            'id': {'type': 'keyword'},
                        }
                    },
                'index_patterns': ['test-log-search-after']
            }
        )
        for _ in range(20):
            counter.add(1)
            client.save(
                'test-log-search-after',
                {
                    'ip': fake.ipv4(),
                    'timestamp': datetime.utcnow(),
                    'id': str(counter)
                }
            )
        client.flush_index('test-log-search-after')
        time.sleep(1)

    def test_create_template(self):
        client.create_template(
            AuthLog.index_name(),
            AuthLog._index.as_template(AuthLog.index_name(),
                                       pattern=AuthLog.index_pattern(),
                                       order=0).to_dict()
        )

    def test_get_template(self):
        client.create_template(
            AuthLog.index_name() + '1',
            AuthLog._index.as_template(AuthLog.index_name(),
                                       pattern=AuthLog.index_pattern() + '1',
                                       order=0).to_dict()
        )

        template = client.get_template(AuthLog.index_name())
        assert template is not None

    def test_delete_template(self):
        client.create_template(
            AuthLog.index_name(),
            AuthLog._index.as_template(AuthLog.index_name(),
                                       pattern=AuthLog.index_pattern(),
                                       order=0).to_dict()
        )

        assert client.delete_template(AuthLog.index_name()) is True
        assert client.delete_template(AuthLog.index_name()) is False

    def test_create_index(self):
        client.create_index(
            'test-create-1',
            {'mappings': {'properties': {'ip': {'type': 'ip'}}}}
        )

        index = client.get_index('test-create-1')
        assert index != {}

    def test_delete_index(self):

        client.delete_index('test-create-1')

        index = client.get_index('test-create-*')
        assert index == {}

    def test_bulk_save(self):
        fake_data = [
            AuthLog(
                ip=fake.ipv4(),
                src_ip=fake.ipv4(),
                src_port=random.randint(1, 500),
                dev_name=fake.text(max_nb_chars=20),
                dev_type='TEST',
                dev_category='TEST',
                log_time=fake.date_time(),
                content=fake.text(),
            )
            for _ in range(100)
        ]
        client.bulk_save(fake_data)
        client.flush_index(AuthLog.index_pattern())
        time.sleep(1)

        result = AuthLog.search().count()

        assert result == 100

    def test_list_index(self):
        indices = ['test-list-index-10000', 'test-list-index-10001',
                   'test-list-index-10002']
        for i in indices:
            client.create_index(i, {})

        list_indices = client.list_index('test-list-index*')
        assert len(list_indices) == 3
        assert indices == list_indices

    def test_delete_index_by_percent(self):
        indices = ['test-delete-index-10000', 'test-delete-index-10001',
                   'test-delete-index-10002', 'test-delete-index-10003',
                   'test-delete-index-10004']
        for i in indices:
            client.create_index(i, {})

        client.delete_index_by_percent('test-delete-index*', 0.2)

        list_indices = client.list_index('test-delete-index*')
        assert len(list_indices) == 4
        assert list_indices == indices[1:]

    def test_search_after(self, logs):
        res = client.search_after(
            'test-log-search-after',
            {
                'sort': [{'timestamp': 'desc'}, {'id': 'desc'}],
                'size': 10,
            })
        result = res['hits']['hits']
        assert len(result) == 10
        res = client.search_after(
            'test-log-search-after',
            {
                'sort': [{'timestamp': 'desc'}, {'id': 'desc'}],
                'size': 10,
                'search_after': result[-1]['sort'],
            })
        result = res['hits']['hits']
        assert len(result) == 10
        res = client.search_after(
            'test-log-search-after',
            {
                'sort': [{'timestamp': 'desc'}, {'id': 'desc'}],
                'size': 10,
                'search_after': result[-1]['sort'],
            })
        result = res['hits']['hits']
        assert len(result) == 0

