from datetime import timedelta

from django.utils import timezone
from faker import Faker

from utils.unified_redis import IPDuplicate, cache, IPDuplicateCleanTask, RedisQueue

fake = Faker()


class TestIPDuplicate:
    def test_is_duplicate_ip(self):
        IPDuplicate(timezone.now()).force_clean()
        ip_duplicate = IPDuplicate(timezone.now())
        ips = [fake.ipv4() for _ in range(20)]

        for i in ips:
            assert ip_duplicate.is_duplicate_ip(i) is False

        for i in ips:
            assert ip_duplicate.is_duplicate_ip(i)

    def test_force_clean(self):
        ip_duplicate = IPDuplicate(timezone.now())
        ip_duplicate.is_duplicate_ip('126.1.1.1')

        assert cache.keys(ip_duplicate.ip_set_pattern + '*') != []
        assert cache.keys(ip_duplicate.duplicate_key) != []

        ip_duplicate.force_clean()
        assert cache.keys(ip_duplicate.ip_set_pattern + '*') == []
        assert cache.keys(ip_duplicate.duplicate_key) == []

    def test_clean_duplicate_key(self):
        """
        当hyperloglog的数据超过上限时，触发清理机制
        """
        IPDuplicate(timezone.now()).force_clean()
        ip_duplicate = IPDuplicate(timezone.now(), threshold=20)
        ips = [fake.ipv4() for _ in range(20)]
        for i in ips:
            assert ip_duplicate.is_duplicate_ip(i) is False
        ip_duplicate.clean_duplicate_key()
        assert cache.keys(ip_duplicate.duplicate_key) != []

        # 造一些昨天的数据，用户hyperloglog恢复
        last_duplicate = IPDuplicate(timezone.now() - timedelta(days=1))
        ips = [fake.ipv4() for _ in range(20)]
        for i in ips:
            last_duplicate.is_duplicate_ip(i)
        ip_duplicate.is_duplicate_ip(fake.ipv4())
        ip_duplicate.clean_duplicate_key()  # 触发清除机制

        assert cache.keys(ip_duplicate.ip_set_pattern + '*') == []
        for i in ips:
            assert last_duplicate.is_duplicate_ip(i)

    def test_run(self):
        IPDuplicate(timezone.now()).force_clean()
        ip_duplicate = IPDuplicate.create_duplicate_ip(timezone.now())
        external = IPDuplicate.create_external_ip(timezone.now())
        ips = [fake.ipv4() for _ in range(10)]
        for i in ips:
            ip_duplicate.is_duplicate_ip(i)
            external.is_duplicate_ip(i)
        IPDuplicateCleanTask.run(timezone.now())
        assert cache.keys(ip_duplicate.ip_set_pattern + '*') == []
        assert cache.keys(external.ip_set_pattern + '*') == []


class TestRedisQueue:
    def test_get_queue(self):
        queue = RedisQueue('test-redis-queue', 5)

    def test_push(self):
        queue = RedisQueue('test-redis-queue', 5)
        for i in range(5):
            queue.push(i)
        assert queue.is_full()

        queue.push(6)
        assert queue.length == 5

    def test_pop(self):
        queue = RedisQueue('test-redis-queue', 5)
        for i in range(5):
            queue.push(i)
        for i in range(5):
            assert queue.pop() == i
        assert queue.pop() is None

    def test_save(self):
        queue = RedisQueue('test-redis-queue', 5)
        for i in range(5):
            queue.push(i)
        queue.save()

        queue = RedisQueue('test-redis-queue', 5)
        assert queue.is_full()
        for i in range(5):
            assert queue.pop() == str(i)
