from datetime import datetime, timedelta
from typing import List
import json
from dateutil import parser

import redis
from django.conf import settings

from utils.helper import get_date
from utils.runnable import TaskRun

rs = redis.StrictRedis.from_url(settings.REDIS_URL)

cache = redis.StrictRedis.from_url(settings.REDIS_URL, decode_responses=True)


class IPDuplicate(object):
    """
    提供IP去重服，使用了Redis的HyperLogLog功能，默认存储100万的数据
    超过100万数据会触发清除机制，清除HyperLogLog数据
    为了减少清除机制的影响，每天会记录一下不重复IP，清除HyperLogLog时，从昨天的数据里恢复
    部分IP
    """
    def __init__(self,
                 current: datetime,
                 threshold=1000000,
                 duplicate_key='duplicate-ip',
                 ip_set_pattern='ip=set'):
        self.current = current
        self.ip_set_pattern = ip_set_pattern
        self.ip_set_key = self.ip_set_pattern + get_date(current)
        self.duplicate_key = duplicate_key
        self.threshold = threshold

    def is_duplicate_ip(self, ip: str):
        cache.sadd(self.ip_set_key, ip)
        if cache.pfadd(self.duplicate_key, ip):
            return False
        return True

    def clean_duplicate_key(self):
        """
        清除hyperloglog，并通过set重建新的hyperloglog
        :return:
        """
        count = cache.pfcount(self.duplicate_key)
        if count > self.threshold:
            cache.delete(self.duplicate_key)
            self._rebuild_duplicate_key()
        for key in cache.keys(self.ip_set_pattern + '*'):
            cache.delete(key)

    def _rebuild_duplicate_key(self):
        self.ip_set_key = self.ip_set_pattern + get_date(
            self.current - timedelta(days=1))
        cursor = 0
        while True:
            cursor, ip_set = cache.sscan(self.ip_set_key, cursor)
            for i in ip_set:
                cache.pfadd(self.duplicate_key, i)
            if cursor == 0:
                break

    def force_clean(self):
        keys = cache.keys(self.ip_set_pattern + '*')
        keys.append(self.duplicate_key)
        for k in keys:
            cache.delete(k)

    @classmethod
    def create_external_ip(cls, current: datetime):
        return cls(current, duplicate_key='external-ip-hyper',
                   ip_set_pattern='external-ip-set')

    @classmethod
    def create_duplicate_ip(cls, current: datetime):
        return cls(current, duplicate_key='duplicate-ip-hyper',
                   ip_set_pattern='duplicate-ip-set')


class IPDuplicateCleanTask(TaskRun):
    @classmethod
    def run(cls, current: datetime):
        """
        定期执行的hyperloglog清理任务
        :param current:
        :return:
        """
        ip_duplicate = IPDuplicate.create_duplicate_ip(current)
        ip_duplicate.clean_duplicate_key()
        external = IPDuplicate.create_external_ip(current)
        external.clean_duplicate_key()


class RedisQueue(object):
    """
    缓存队列，为了优化性能，初始化之后，在内存中维护队列，最后用save存到redis中
    """
    def __init__(self, key: str, cap: int):
        self._key = key
        self._cap = cap
        self._queue = self._initial_queue()

    def _initial_queue(self) -> List:
        """
        初始化队列
        :return:
        """
        res = cache.lrange(self._key, 0, self._cap-1)[::-1]
        return res

    @property
    def length(self):
        return len(self._queue)

    def save(self):
        cache.delete(self._key)
        cache.lpush(self._key, *self._queue)

    @property
    def data(self):
        return self._queue

    def push(self, item):
        if self.is_full():
            self.pop()
        self._queue.append(item)

    def is_full(self):
        return len(self._queue) >= self._cap

    def is_empty(self):
        return len(self._queue) == 0

    def pop(self):
        if not self.is_empty():
            return self._queue.pop(0)
        return None


class IPRedisQueue(RedisQueue):
    def _initial_queue(self) -> List:
        res = cache.lrange(self._key, 0, self._cap-1)[::-1]
        data = []
        for r in res:
            d = json.loads(r)
            d['update_time'] = parser.parse(d['update_time'])
            data.append(d)
        return data

    def save(self):
        cache.delete(self._key)
        data = []
        for i in self._queue:
            i['update_time'] = i['update_time'].isoformat()
            data.append(json.dumps(i))
        if data:
            cache.lpush(self._key, *data)

    def set(self, data):
        self._queue = data
        self.save()
