from threading import Thread
import time

import pytest

from utils.async_lock import RedisLock, ForceDropError


LOCK = 1
OVERTIME = 1
BLOCK = 1
DELAY = 1


def normal():
    global LOCK
    with RedisLock('normal'):
        time.sleep(0.2)
        LOCK = -LOCK


def overtime():
    global OVERTIME
    with RedisLock('overtime'):
        time.sleep(2)
        OVERTIME = -OVERTIME


def block_second():
    global BLOCK
    try:
        with RedisLock('block_second', force_drop=True):
            time.sleep(0.5)
            BLOCK = -BLOCK
    except ForceDropError as e:
        print(e)


def delay_lock():
    global DELAY
    try:
        with RedisLock('delay_lock', force_drop=True, delay=1):
            DELAY = -DELAY
    except ForceDropError as e:
        print(e)


class TestAsyncLock:

    def test_normal(self):
        threads = [
            Thread(target=normal), Thread(target=normal)
        ]
        for t in threads:
            t.start()

        for t in threads:
            t.join()

        assert LOCK == 1

    def test_overtime(self):
        threads = [
            Thread(target=overtime), Thread(target=overtime)
        ]
        for t in threads:
            t.start()

        for t in threads:
            t.join()

        assert OVERTIME == 1

    def test_block_second(self):
        """
        第二个需要被阻塞丢弃
        """
        threads = [
            Thread(target=block_second), Thread(target=block_second)
        ]
        for t in threads:
            t.start()

        for t in threads:
            t.join()

        assert BLOCK == -1

    def test_delay_lock(self):
        """
        第一个获取锁后，延迟释放
        """
        threads = [
            Thread(target=delay_lock), Thread(target=delay_lock)
        ]
        for t in threads:
            t.start()

        for t in threads:
            t.join()

        assert DELAY == -1
