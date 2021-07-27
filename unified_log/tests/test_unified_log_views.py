import random
import time
from typing import Dict, List

import pytest
from django.urls import reverse
from faker import Faker
from rest_framework import status
from rest_framework.test import APIClient

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from unified_log.elastic.elastic_model import AuthLog, BaseDocument
from unified_log.factory_data import LogProcessRuleFactory, \
    LogProcessTemplateFactory
from unified_log.filters import LogSearchFilter
from unified_log.models import *
from unified_log.serializers import LogTemplateCreateSerializer
from utils.base_testcase import BaseViewTest, \
    authenticate_read_only, config_engineer_permission_create, \
    config_engineer_permission_delete, config_engineer_permission_update
from utils.core.exceptions import CustomError, CustomValidationError

fake = Faker()


# @pytest.mark.skip
@pytest.mark.django_db
class TestLogRuleView(BaseViewTest):
    # @pytest.mark.skip
    @authenticate_read_only
    def test_permissions(self, all_client: Dict[str, APIClient], user: str,
                         expect_code: int):
        client = all_client[user]

        response = client.get(reverse('log-rule-list'))

        assert response.status_code == expect_code

        response = client.get(reverse('log-rule-detail', args=(1,)))

        assert response.status_code == expect_code

    def test_log_rule_list(self, audit_client: APIClient):
        rule = LogProcessRuleFactory.create(
            name='测试日志规则', category=1, type=1, brand='木链', hardware='综管',
        )
        LogProcessTemplateFactory.create(kern=rule)

        response = audit_client.get(
            reverse('log-rule-list'),
            data={
                'name': '测试', 'category': 1, 'type': 1, 'brand': '木链',
                'hardware': '综管', 'page': 1,
            },
            format='json',
        )

        assert response.data['page_count'] == 1

    def test_log_rule_detail(self, audit_client: APIClient):
        rule = LogProcessRuleFactory.create(
            name='测试日志规则', category=1, type=1, brand='木链', hardware='综管',
        )

        response = audit_client.get(
            reverse('log-rule-detail', args=(rule.id,)),
            format='json'
        )
        assert response.data['name'] == rule.name

    def test_log_rule_list_all(self, audit_client: APIClient):
        """
        不传递page参数时，需要返回所有的规则
        """
        rule = LogProcessRuleFactory.create_batch(30)
        response = audit_client.get(reverse('log-rule-list'))

        assert len(response.data) == LogProcessRule.objects.count()


# @pytest.mark.skip
@pytest.mark.django_db
class TestLogTemplateView(BaseViewTest):
    @authenticate_read_only
    def test_permissions(self, all_client: Dict[str, APIClient], user: str,
                         expect_code: int):
        client = all_client[user]

        response = client.get(reverse('log-template-list'))

        assert response.status_code == expect_code

        response = client.get(reverse('log-template-detail', args=(1,)))

        assert response.status_code == expect_code

    @config_engineer_permission_create
    def test_create_permissions(self, all_client: Dict[str, APIClient],
                                user: str, expect_code: int):
        client = all_client[user]
        LogProcessTemplateFactory.create()
        template = LogProcessTemplate.objects.last()
        data = LogTemplateCreateSerializer(template).data
        data['name'] = '测试模板'

        response = client.post(
            reverse('log-template-list'),
            data=data,
            format='json'
        )

        assert response.status_code == expect_code

    @config_engineer_permission_delete
    def test_delete_permissions(self, all_client: Dict[str, APIClient],
                                user: str, expect_code: int):
        client = all_client[user]
        template = LogProcessTemplateFactory.create(add=MANUAL_ADD)

        response = client.delete(
            reverse('log-template-detail', args=(template.id,)),
            format='json'
        )

        assert response.status_code == expect_code

    @config_engineer_permission_update
    def test_update_permissions(self, all_client: Dict[str, APIClient],
                                user: str, expect_code: int):
        client = all_client[user]
        t = LogProcessTemplateFactory.create(add=MANUAL_ADD)
        template = LogProcessTemplate.objects.get(id=t.id)
        data = LogTemplateCreateSerializer(template).data
        data['name'] = '测试模板'

        response = client.put(
            reverse('log-template-detail', args=(template.id,)),
            data=data,
            format='json'
        )
        assert response.status_code == expect_code

    def test_get_template(self, config_client: APIClient):
        template = LogProcessTemplateFactory.create(
            name='测试日志规则模板', category=1, type=1, brand='木链',
            hardware='综管',
        )
        DeviceFactory.create_batch(20, log_template=template,
                                   strategy_apply_status=
                                   Device.STRATEGY_APPLY_STATUS_UN_APPLIED)

        response = config_client.get(
            reverse('log-template-list'),
            data={
                'name': '测试', 'category': 1, 'type': 1, 'brand': '木链',
                'hardware': '综管', 'page': 1
            },
            format='json',
        )

        assert response.data['page_count'] == 1
        assert response.data['results'][0]['device_count'] == 20

    def test_get_template_no_page(self, config_client: APIClient):
        """
        不传page参数不进行分页
        """
        template = LogProcessTemplateFactory.create()
        response = config_client.get(
            reverse('log-template-list'),
            data={},
        )

        assert len(response.data) == LogProcessTemplate.objects.filter().count()

    def test_create_template(self, config_client: APIClient):
        rules: List[LogProcessRule] = LogProcessRuleFactory.create_batch(
            size=10)
        name = 'ashhdsad'
        data = {'name': name,
                'category': LogProcessTemplateFactory.category.function(),
                'type': LogProcessTemplateFactory.type.function(),
                'rules': {
                    'kern': {'id': rules[0].id},
                    'auth': {'id': rules[0].id},
                    'syslog': {'id': rules[0].id},
                    'local0': {'id': rules[1].id},
                    'local1': {'id': rules[8].id},
                    'local2': {'id': rules[9].id},
                    'local3': {'id': rules[1].id},
                }
                }
        response = config_client.post(
            reverse('log-template-list'),
            data=data,
            format='json'
        )
        assert response.status_code == status.HTTP_201_CREATED

        template = LogProcessTemplate.objects.get(name=name)
        assert template.kern_id == rules[0].id
        assert template.add == 2

    def test_create_duplicated_template(self, config_client: APIClient):
        """
        相同category，type下的name不能重复
        """
        name = 'a12'
        LogProcessTemplateFactory.create(name=name, category=1, type=1)
        data = {'name': name,
                'category': 1,
                'type': 1,
                'rules': {},
                }
        response = config_client.post(
            reverse('log-template-list'),
            data=data,
            format='json'
        )
        assert response.status_code == CustomError.status_code
        assert response.data == CustomValidationError(
            CustomValidationError.REPEATED_NAME_CATEGORY_TYPE_ERROR).detail

    def test_update_duplicated_template(self, config_client: APIClient):
        """
        修改模板时，name，category，type要和其他模板不同，但是不能影响到自己的修改
        """
        LogProcessRuleFactory.create_batch(20)
        template = LogProcessTemplateFactory.create(
            type=1, category=1, name='123', add=MANUAL_ADD)
        serializer = LogTemplateCreateSerializer(template)
        data = serializer.data

        # 修改同一个模板时，禁止重名机制不用生效
        response = config_client.put(
            reverse('log-template-detail', args=(template.id,)),
            data=data,
            format='json'
        )

        assert response.status_code == status.HTTP_200_OK

        # 在已存在一个模板，然后另一个模板也要修改名字和原来的模板一样时，需要报错
        template = LogProcessTemplateFactory.create(
            type=1, category=1, name='234', add=MANUAL_ADD)
        serializer = LogTemplateCreateSerializer(template)
        data = serializer.data
        data['name'] = '123'
        response = config_client.put(
            reverse('log-template-detail', args=(template.id,)),
            data=data,
            format='json',
        )
        assert response.data == CustomValidationError(
            CustomValidationError.REPEATED_NAME_CATEGORY_TYPE_ERROR).detail

    def test_delete_template(self, config_client: APIClient):
        template = LogProcessTemplateFactory.create(add=MANUAL_ADD)

        response = config_client.delete(
            reverse('log-template-detail', args=(template.id,)),
        )

        assert response.status_code == status.HTTP_204_NO_CONTENT
        with pytest.raises(LogProcessTemplate.DoesNotExist):
            LogProcessTemplate.objects.get(name=template.name)

        template = LogProcessTemplateFactory.create(add=SYSTEM_ADD)
        response = config_client.delete(
            reverse('log-template-detail', args=(template.id,))
        )

        assert response.status_code == CustomError.status_code
        assert response.data['error'] == \
               str(CustomError.UN_ALLOWED_TO_DELETE_SYSTEM_TEMPLATE)

    def test_update_template(self, config_client: APIClient):
        template = LogProcessTemplateFactory.create(add=MANUAL_ADD)
        rule = LogProcessRuleFactory.create()

        data = LogTemplateCreateSerializer(template).data
        data['name'] = LogProcessTemplateFactory.category.function()
        data['rules'] = {
            'kern': {'id': rule.id},
            'auth': {'id': rule.id}
        }

        response = config_client.put(
            reverse('log-template-detail', args=(template.id,)),
            data=data,
            format='json'
        )

        template = LogProcessTemplate.objects.get(name=data['name'])
        assert response.status_code == status.HTTP_200_OK
        assert template.kern_id == rule.id
        assert template.auth_id == rule.id

        template = LogProcessTemplateFactory.create(add=SYSTEM_ADD)
        data = LogTemplateCreateSerializer(template).data

        response = config_client.put(
            reverse('log-template-detail', args=(template.id,)),
            data=data,
            format='json'
        )

        assert response.status_code == CustomError.status_code
        assert response.data['error'] == \
               str(CustomError.UN_ALLOWED_TO_EDIT_SYSTEM_TEMPLATE)


# @pytest.mark.skip
@pytest.mark.django_db
class TestDeviceLogView(BaseViewTest):
    def test_update_log_status(self, config_client: APIClient):
        devices = DeviceFactory.create_batch(
            20, strategy_apply_status=Device.STRATEGY_APPLY_STATUS_UN_APPLIED)
        ids = [t.id for t in devices]
        response = config_client.put(
            reverse('device-batch'),
            data={
                'ids': ids,
                'log_status': False,
            },
            format='json',
        )

        assert response.status_code == status.HTTP_200_OK

        assert Device.objects.filter(id__in=ids, log_status=False).count() == 20


# @pytest.mark.skip
@pytest.mark.django_db
class TestSearchView(BaseViewTest):
    log = dict(
        ip=fake.ipv4(),
        src_ip=fake.ipv4(),
        src_port=random.randint(10, 100),
        dst_ip=fake.ipv4(),
        dst_port=random.randint(10, 100),
        dev_name=fake.text(max_nb_chars=10),
        dev_category=fake.text(max_nb_chars=10),
        dev_type=fake.text(max_nb_chars=10),
        content=fake.text(),
        timestamp=fake.date_time(),
        log_time=fake.date_time(),
        status=True,
    )

    @authenticate_read_only
    def test_permissions(self, all_client: Dict[str, APIClient], user: str,
                         expect_code: int):
        client = all_client[user]

        response = client.post(
            reverse('log-search'),
            data={
                'size': 10,
                'query': {},
            },
            format='json'
        )

        assert response.status_code == expect_code

    def test_search_filter(self):
        query = self.log.copy()
        query.pop('timestamp')
        query.pop('log_time')
        query['timestamp_gt'] = fake.date_time_this_month(before_now=True)
        query['timestamp_lt'] = fake.date_time_this_month(after_now=True)
        query['log_time_gt'] = fake.date_time_this_month(before_now=True)
        query['log_time_lt'] = fake.date_time_this_month(after_now=True)

        search = LogSearchFilter(**query)

        target = {'query': {'bool': {
            'filter': [{'match': {'ip': query['ip']}},
                       {'match': {'src_ip': query['src_ip']}},
                       {'match': {'src_port': query['src_port']}},
                       {'match': {'dst_ip': query['dst_ip']}},
                       {'match': {'dst_port': query['dst_port']}},
                       {'match': {'dev_name': query['dev_name']}},
                       {'match': {'dev_category': query['dev_category']}},
                       {'match': {'dev_type': query['dev_type']}},
                       {'match': {'content': query['content']}},
                       {'term': {'status': True}},
                       {'range': {'timestamp': {
                           'gt': query['timestamp_gt'],
                           'lt': query['timestamp_lt']}}},
                       {'range': {'log_time': {
                           'gt': query['log_time_gt'],
                           'lt': query['log_time_lt']}}}]}}}

        assert target == search.get_query()

    def test_search(self, config_client: APIClient):
        log = self.log.copy()
        log['content'] = 'Get a DateTime object based on a random date between ' \
                         'two given dates. Accepts date strings that can be ' \
                         'recognized by strtotime().'
        log = AuthLog(**log)
        log.save()
        time.sleep(1)
        query = self.log.copy()
        query.pop('timestamp')
        query.pop('log_time')
        query['content'] = 'datetime random accepts'

        response = config_client.post(
            reverse('log-search'),
            data=query,
            format='json'
        )

        assert response.data.get('scroll_id') is not None
        assert len(response.data['results']) == 1

    def test_search_more(self, config_client: APIClient):
        logs = [AuthLog(**self.log) for _ in range(20)]
        for log in logs:
            log.save()
        time.sleep(1)
        scroll_id = None
        response = None

        count = BaseDocument.search().count()

        for _ in range(count // 10 + 2):
            response = config_client.post(
                reverse('log-search'),
                data={
                    'scroll_id': scroll_id,
                    'page_size': 10,
                },
                format='json'
            )

            scroll_id = response.data['scroll_id']
        assert response.data['results'] == []


@pytest.mark.django_db
class TestRawSearchView(BaseViewTest):
    log = dict(
        ip=fake.ipv4(),
        dev_name=fake.text(max_nb_chars=10),
        dev_category=fake.text(max_nb_chars=10),
        dev_type=fake.text(max_nb_chars=10),
        content=fake.text(),
        timestamp=fake.date_time(),
        status=False,
    )

    @authenticate_read_only
    def test_permissions(self, all_client: Dict[str, APIClient], user: str,
                         expect_code: int):
        client = all_client[user]

        response = client.post(
            reverse('log-raw-search'),
            data={
                'size': 10,
            },
            format='json'
        )

        assert response.status_code == expect_code

    def test_search_filter(self):
        query = self.log.copy()
        query.pop('timestamp')
        query.pop('status')
        query['timestamp__gt'] = fake.date_time_this_month(before_now=True)
        query['timestamp__lt'] = fake.date_time_this_month(after_now=True)

        search = LogSearchFilter(**query)

        target = {'query': {'bool': {
            'filter': [{'match': {'ip': query['ip']}},
                       {'match': {'dev_name': query['dev_name']}},
                       {'match': {'dev_category': query['dev_category']}},
                       {'match': {'dev_type': query['dev_type']}},
                       {'match': {'content': query['content']}},
                       {'range': {'timestamp': {
                           'gt': query['timestamp__gt'],
                           'lt': query['timestamp__lt']}}},
                       ]}}}

        assert target == search.get_query()

    def test_search(self, config_client: APIClient):
        log = self.log.copy()
        log['content'] = 'Get a DateTime object based on a random date between ' \
                         'two given dates. Accepts date strings that can be ' \
                         'recognized by strtotime().'
        log = BaseDocument(**log)
        log.save()
        time.sleep(1)
        query = self.log.copy()
        query.pop('timestamp')
        query.pop('status')
        query['content'] = 'datetime random accepts'

        response = config_client.post(
            reverse('log-raw-search'),
            data=query,
            format='json'
        )

        assert response.data.get('scroll_id') is not None
        assert len(response.data['results']) == 1

    def test_search_more(self, config_client: APIClient):
        logs = [BaseDocument(**self.log) for _ in range(20)]
        for log in logs:
            log.save()
        time.sleep(1)
        scroll_id = None
        response = None

        count = BaseDocument.search().count()

        for _ in range(count // 10 + 2):
            response = config_client.post(
                reverse('log-raw-search'),
                data={
                    'scroll_id': scroll_id,
                    'page_size': 10,
                },
                format='json'
            )
            scroll_id = response.data['scroll_id']
        assert response.data['results'] == []


@pytest.mark.django_db
class TestSearchAfterView(BaseViewTest):
    log = dict(
        ip=fake.ipv4(),
        src_ip=fake.ipv4(),
        src_port=random.randint(10, 100),
        dst_ip=fake.ipv4(),
        dst_port=random.randint(10, 100),
        dev_name=fake.text(max_nb_chars=10),
        dev_category=fake.text(max_nb_chars=10),
        dev_type=fake.text(max_nb_chars=10),
        content=fake.text(),
        timestamp=fake.date_time(),
        log_time=fake.date_time(),
        status=True,
    )

    @authenticate_read_only
    def test_permissions(self, all_client: Dict[str, APIClient], user: str,
                         expect_code: int):
        client = all_client[user]

        response = client.post(
            reverse('log-search-after'),
            data={
                'page_size': 10,
                'query': {},
            },
            format='json'
        )

        assert response.status_code == expect_code

    def test_search_filter(self):
        query = self.log.copy()
        query.pop('timestamp')
        query.pop('log_time')
        query['timestamp_gt'] = fake.date_time_this_month(before_now=True)
        query['timestamp_lt'] = fake.date_time_this_month(after_now=True)
        query['log_time_gt'] = fake.date_time_this_month(before_now=True)
        query['log_time_lt'] = fake.date_time_this_month(after_now=True)

        search = LogSearchFilter(**query)

        target = {'query': {'bool': {
            'filter': [{'match': {'ip': query['ip']}},
                       {'match': {'src_ip': query['src_ip']}},
                       {'match': {'src_port': query['src_port']}},
                       {'match': {'dst_ip': query['dst_ip']}},
                       {'match': {'dst_port': query['dst_port']}},
                       {'match': {'dev_name': query['dev_name']}},
                       {'match': {'dev_category': query['dev_category']}},
                       {'match': {'dev_type': query['dev_type']}},
                       {'match': {'content': query['content']}},
                       {'term': {'status': True}},
                       {'range': {'timestamp': {
                           'gt': query['timestamp_gt'],
                           'lt': query['timestamp_lt']}}},
                       {'range': {'log_time': {
                           'gt': query['log_time_gt'],
                           'lt': query['log_time_lt']}}}]}}}

        assert target == search.get_query()

    def test_search(self, config_client: APIClient):
        log = self.log.copy()
        log['content'] = 'Get a DateTime object based on a random date between ' \
                         'two given dates. Accepts date strings that can be ' \
                         'recognized by strtotime().'
        log = AuthLog(**log)
        log.save()
        time.sleep(1)
        query = self.log.copy()
        query.pop('timestamp')
        query.pop('log_time')
        query['content'] = 'datetime random accepts'

        response = config_client.post(
            reverse('log-search'),
            data=query,
            format='json'
        )

        assert len(response.data['results']) == 1

    def test_search_more(self, config_client: APIClient):
        logs = [AuthLog(**self.log) for _ in range(20)]
        for log in logs:
            log.save()
        time.sleep(1)
        after = None
        response = None

        count = BaseDocument.search().count()

        for _ in range(count // 10 + 2):
            response = config_client.post(
                reverse('log-search-after'),
                data={
                    'after': after,
                    'page_size': 10,
                },
                format='json'
            )
            if not response.data['results']:
                break
            after = response.data['after']
        assert response.data['results'] == []


@pytest.mark.django_db
class TestRawSearchAfterView(BaseViewTest):
    log = dict(
        ip=fake.ipv4(),
        dev_name=fake.text(max_nb_chars=10),
        dev_category=fake.text(max_nb_chars=10),
        dev_type=fake.text(max_nb_chars=10),
        content=fake.text(),
        timestamp=fake.date_time(),
        status=False,
    )

    @authenticate_read_only
    def test_permissions(self, all_client: Dict[str, APIClient], user: str,
                         expect_code: int):
        client = all_client[user]

        response = client.post(
            reverse('log-raw-search-after'),
            data={
                'size': 10,
            },
            format='json'
        )

        assert response.status_code == expect_code

    def test_search_filter(self):
        query = self.log.copy()
        query.pop('timestamp')
        query.pop('status')
        query['timestamp__gt'] = fake.date_time_this_month(before_now=True)
        query['timestamp__lt'] = fake.date_time_this_month(after_now=True)

        search = LogSearchFilter(**query)

        target = {'query': {'bool': {
            'filter': [{'match': {'ip': query['ip']}},
                       {'match': {'dev_name': query['dev_name']}},
                       {'match': {'dev_category': query['dev_category']}},
                       {'match': {'dev_type': query['dev_type']}},
                       {'match': {'content': query['content']}},
                       {'range': {'timestamp': {
                           'gt': query['timestamp__gt'],
                           'lt': query['timestamp__lt']}}},
                       ]}}}

        assert target == search.get_query()

    def test_search(self, config_client: APIClient):
        log = self.log.copy()
        log['content'] = 'Get a DateTime object based on a random date between ' \
                         'two given dates. Accepts date strings that can be ' \
                         'recognized by strtotime().'
        log = BaseDocument(**log)
        log.save()
        time.sleep(1)
        query = self.log.copy()
        query.pop('timestamp')
        query.pop('status')
        query['content'] = 'datetime random accepts'

        response = config_client.post(
            reverse('log-raw-search'),
            data=query,
            format='json'
        )

        assert len(response.data['results']) == 1

    def test_search_more(self, config_client: APIClient):
        logs = [BaseDocument(**self.log) for _ in range(20)]
        for log in logs:
            log.save()
        time.sleep(1)
        after = None
        response = None

        count = BaseDocument.search().count()

        for _ in range(count // 10 + 2):
            response = config_client.post(
                reverse('log-raw-search-after'),
                data={
                    'after': after,
                    'page_size': 10,
                },
                format='json'
            )
            if not response.data['results']:
                break
            after = response.data['after']
        assert response.data['results'] == []
