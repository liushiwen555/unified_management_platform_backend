from typing import Dict, List
import logging
import time

from django.conf import settings

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from elasticsearch_dsl import connections, Document
from elasticsearch.exceptions import NotFoundError


try:
    connections.create_connection(hosts=[settings.ELASTICSEARCH_HOST], timeout=60)
except Exception as e:
    logging.error('elasticsearch连接失败, {}'.format(e))
    logging.warning('尝试重连中...')
    time.sleep(3 * 60)
    connections.create_connection(hosts=[settings.ELASTICSEARCH_HOST], timeout=60)


class ElasticClient(object):
    def __init__(self):
        self._client = Elasticsearch(settings.ELASTICSEARCH_HOST)
        self._indices = self._client.indices
        self.connection = connections.get_connection()

    def get_template(self, template_name: str = None) -> Dict:
        """
        获取索引模板的内容
        :param template_name: 索引模板名称
        :return: {'template_name': {setting}
        """
        return self._indices.get_template(template_name)

    def delete_template(self, template_name: str) -> bool:
        """
        删除索引模板
        :param template_name:  索引模板名称
        :return: 删除结果
        """
        try:
            res = self._indices.delete_template(template_name)
        except NotFoundError:
            return False

        try:
            return res['acknowledged']
        except KeyError:
            return False

    def create_template(self, template_name: str, body: Dict):
        """
        创建索引模板
        :param template_name: 模板名称
        :param body: 索引模板的配置内容，包括匹配的索引模式，索引字段类型，索引的分片等
        {
        'mappings':
            {'properties':
                {
                'ip': {'type': 'ip'},
                'src_ip': {'type': 'ip'}
                }
            }
        'index_patterns': ['log-auth*']
        }
        :return:
        """
        self._indices.put_template(template_name, body)

    def save(self, index_name: str, data: Dict):
        self._client.index(index_name, data)

    def delete_index(self, index_name: str) -> bool:
        """
        删除索引
        :param index_name:  索引名，可以使用通配符，或者','分隔多个
        :return: 删除结果
        """
        try:
            res = self._indices.delete(index_name, allow_no_indices=True)
        except NotFoundError:
            return False

        try:
            return res['acknowledged']
        except KeyError:
            return False

    def create_index(self, index_name: str, body: Dict):
        """
        创建索引
        :param index_name:
        :param body:
        {
            'mappings': {
                'properties': {
                    'field': {'type': 'keyword'},
                }
            },
            'aliases': [],
            'settings': {}
        }
        :return:
        """
        self._indices.create(index_name, body)

    def get_index(self, index_name: str = None) -> Dict:
        """
        查询索引
        :param index_name: 索引名，可以使用通配符，或者','分隔多个
        :return: 索引的配置信息
        """
        return self._indices.get(index_name)

    def search(self, index_name, body) -> Dict:
        return self._client.search(index=index_name, body=body)

    def bulk_save(self, documents: List[Document]):
        """
        批量存储日志
        :param documents: 通过DSL的ORM实例化好的日志对象
        """
        bulk(self.connection, [d.to_dict(True) for d in documents])

    def flush_index(self, index_name: str = None):
        """
        存入elasticsearch的数据一般需要等1s才能查到，使用flush强制刷新
        :param index_name: 索引名，可以使用通配符，或者','分隔多个
        """
        self._indices.flush(index_name, params={'force': 'true'})

    def search_with_scroll(self, index: str, body: Dict, scroll_time='5m'):
        """
        使用scroll的查询，用于初次查询没有scroll的情况
        :param index: 索引模式
        :param body: 查询体
        :param scroll_time: scroll缓存的持续时间
        :return: 查询结果
        """
        res = self._client.search(index=index, body=body, scroll=scroll_time,
                                  timeout='120s')
        return res

    def scroll(self, scroll_id: str, scroll_time='5m'):
        """
        使用scroll_id的查询，用于获取到初次查询的scroll_id的情况
        :param scroll_id: @search_with_scroll 返回的scroll_id
        :param scroll_time: scroll缓存的持续时间
        :return: 查询结果
        """
        return self._client.scroll(scroll_id=scroll_id, scroll=scroll_time)

    def list_index(self, index: str):
        """
        获取按时间排序的所有符合index的索引
        :param index: 索引模式
        :return: 索引列表
        """
        indices = self._client.cat.indices(index, h='index', s='creation.date')
        indices = indices.split('\n')
        if indices and indices[-1] == '':
            indices = indices[:-1]
        return indices

    def delete_index_by_percent(self, index: str, percent: float):
        """
        删除前百分之几的索引，根据时间排序
        :param index: 索引模式
        :param percent: 小数，0.2，表示删除最早的0.2的索引
        """
        indices = self.list_index(index)
        total = len(indices)
        to_delete = indices[:round(total * percent)]
        for i in to_delete:
            self.delete_index(i)

    def search_after(self, index: str, body: Dict, after: List = None) -> Dict:
        """
        https://www.elastic.co/guide/en/elasticsearch/reference/7.10/paginate-search-results.html#search-after
        利用search_after做滚动加载，需要使用timestamp和id作为加载的标准
        :param index: 索引模式
        :param body: 查询条件，分页大小，排序字段等内容
        :param after: 上次搜索结果的最后一条数据里的sort字段数据
        :return: 返回新的后续结果
        """
        if after:
            body.update({
                'search_after': after,
            })
        return self._client.search(index=index, body=body)


client = ElasticClient()
