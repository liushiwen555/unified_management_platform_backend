from typing import Dict

from django_filters import rest_framework as filters
from elasticsearch_dsl import Search

from utils.core.filters import BaseFilters
from unified_log.models import LogProcessRule, LogProcessTemplate
from unified_log.elastic.elastic_model import BaseDocument


class LogRuleFilter(BaseFilters):
    name = filters.CharFilter(field_name='name', lookup_expr='contains')
    brand = filters.CharFilter(field_name='brand', lookup_expr='contains')
    hardware = filters.CharFilter(field_name='hardware', lookup_expr='contains')
    category = filters.NumberFilter(field_name='category', help_text='系统类别')
    type = filters.NumberFilter(field_name='type', help_text='系统类型')
    add = filters.NumberFilter(field_name='add', help_text='添加方式')

    class Meta:
        model = LogProcessRule
        fields = ('category',)


class LogTemplateFilter(BaseFilters):
    name = filters.CharFilter(field_name='name', lookup_expr='contains')
    brand = filters.CharFilter(field_name='brand', lookup_expr='contains')
    hardware = filters.CharFilter(field_name='hardware', lookup_expr='contains')
    category = filters.NumberFilter(field_name='category', help_text='资产类别')
    type = filters.NumberFilter(field_name='type', help_text='资产类型')
    add = filters.NumberFilter(field_name='add', help_text='添加方式')

    class Meta:
        model = LogProcessTemplate
        fields = ('category', 'type', 'add')


class LogSearchFilter:
    class Meta:
        model = BaseDocument
        search_mappings = {
            'ip': 'match',
            'src_ip': 'match',
            'src_port': 'match',
            'dst_ip': 'match',
            'dst_port': 'match',
            'dev_name': 'match',
            'dev_type': 'match',
            'dev_category': 'match',
            'log_time': 'range',
            'timestamp': 'range',
            'status': 'term',
            'content': 'match',
            'protocol': 'term',
        }

    def __init__(self, *args, **kwargs):
        self.mappings = self.Meta.search_mappings
        self.search: Search = self.Meta.model.search()
        self.form(**kwargs)

    def form(self, **kwargs) -> Search:
        """
        从request body里的查询参数拼接重Elasticsearch的查询，调用的是elasticsearch-dsl
        的查询https://elasticsearch-dsl.readthedocs.io/en/latest/search_dsl.html
        :param kwargs: 所有查询条件
        :return: 查询实例
        """
        if not kwargs:
            return self.search
        timestamp = {}
        log_time = {}

        for key, value in kwargs.items():
            if value in ['', None]:
                continue
            if 'timestamp' in key:
                timestamp[key.split('_')[-1]] = value
            elif 'log_time' in key:
                log_time[key.split('_')[-1]] = value
            elif key in self.mappings:
                self.search = self.search.filter(self.mappings[key],
                                                 **{key: value})
        if timestamp:
            self.search = self.search.filter(self.mappings['timestamp'],
                                             timestamp=timestamp)
        if log_time:
            self.search = self.search.filter(self.mappings['log_time'],
                                             log_time=log_time)
        return self.search

    def sort(self, sort) -> Search:
        """
        对查询结果进行排序
        :param sort: 排序的字符串，如'-timestamp'
        :return: 排序后的search实例
        """
        self.search = self.search.sort(sort)
        return self.search

    def get_query(self) -> Dict:
        """
        将search的实例转换为elasticsearch的请求接口body
        :return:
        {'query':
            {'bool':
                {'filter':
                    [
                        {'match': {'content': 'hello'}},
                        {'match': {'dev_name': 'hello'}},
                    ]
                }
            }
        }
        """
        return self.search.to_dict()
