"""
线程安全的计数器
"""
from typing import Dict, Union
from abc import ABC, abstractmethod
import threading

_counter = threading.local()
_counter.val = 0


class AbstractCounter(ABC):
    """
    不要直接使用计数器实例化一个对象
    而是要使用对应的工厂get_counter()去获取。在同一个线程内，多处get_counter()获取的
    均是同一个计数器，差不多是线程的本地变量
    """
    @abstractmethod
    def add(self, num) -> int:
        pass

    @abstractmethod
    def sub(self, num) -> int:
        pass

    @property
    def value(self):
        return None

    @property
    def thread_id(self):
        return None

    @abstractmethod
    def destroy(self):
        """
        用完记得销毁，否则一次同样线程id的线程进来的时候，就会使用了上次的计数器
        :return:
        """
        pass


class _GlobalCounter(AbstractCounter):
    """
    伪线程安全的计数器，实际上是线程安全的，并且主线程还能获取到子线程的计算结果，速度比
    _LocalCounter快很多，但是略逊色threading.local()获取的计数器
    """
    def __init__(self, thread_id: int, key: str, refresh=None):
        self._key = key
        self._val = 0
        self._thread_id = thread_id
        self._refresh = refresh

    def add(self, num=1) -> int:
        self._val += num
        self.refresh()
        return self._val

    def sub(self, num=1) -> int:
        self._val -= num
        return self._val

    @property
    def value(self) -> int:
        return self._val

    @property
    def thread_id(self) -> int:
        return self._thread_id

    def refresh(self):
        if not self._refresh:
            return
        if self._val >= self._refresh:
            self._val = 0

    def destroy(self):
        GlobalFactory.destroy(self._thread_id)

    def __str__(self):
        return str(self._key) + str(self._val)


class _LocalCounter(AbstractCounter):
    """
    真线程安全的计数器，效率稍逊一下_GlobalCounter，但是可以使用get_inner_counter()获取
    内部的counter，直接使用counter计算会快很多
    """
    def __init__(self, thread_id, key, refresh: int):
        self._counter = _counter
        self._counter.val = 0
        self._refresh = refresh
        self._key = key
        self._thread_id = thread_id

    def add(self, num=1):
        self._counter.val += num
        self.refresh()
        return self._counter.val

    def sub(self, num=1):
        self._counter.val -= num
        return self._counter.val

    def refresh(self):
        if not self._refresh:
            return
        if self._counter.val >= self._refresh:
            self._counter.val = 0

    @property
    def value(self):
        return self._counter.val

    @property
    def thread_id(self):
        return self._thread_id

    def destroy(self):
        LocalFactory.destroy(self._thread_id)

    def get_inner_counter(self):
        """
        获取实际的线程安全变量counter，
        计算时需要用到属性val
        计算会绕过add()里的检查是否要刷新的流程，所以确保不会太大的结果情况下使用
        counter = get_inner_counter()
        counter.val += 1
        counter.val -= 1
        :return: threading.local()对象
        """
        return self._counter

    def __str__(self):
        return str(self._key) + str(self._counter.val)


class _CounterFactory(object):
    _exists: Dict[Union[int, str], AbstractCounter] = dict()
    _instance = None
    LOG_THRESHOLD: int = 0xffffffff

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    @classmethod
    def get_count(cls, thread_id=None, key: str = None, refresh: int = None) -> Union[_GlobalCounter, _LocalCounter]:
        """
        当不确定计数器会被用在哪个线程，或者线程可以随意创建的时候，不要传入key
        :param thread_id: 线程id，如果在同个线程内不用传，如果要跨线程获取计数器需要传
        :param key: 给某个计数器标示名字
        :param refresh: 可以设置当计数器到达多大时，需要重置回0
        :return: 返回计数器
        """
        if not thread_id:
            thread_id = threading.current_thread().ident
        if thread_id in cls._exists:
            counter = cls._exists[thread_id]
        else:
            counter = cls._get_count(thread_id, key, refresh)
        return counter

    @classmethod
    def _get_count(cls, thread_id, key, refresh) -> Union[_GlobalCounter, _LocalCounter]:
        raise NotImplementedError('必须实现_get_count方法')

    @classmethod
    def destroy(cls, thread_id: int):
        if thread_id in cls._exists:
            cls._exists.pop(thread_id)

    @classmethod
    def exists(cls, key) -> bool:
        return key in cls._exists


class GlobalFactory(_CounterFactory):
    _exists: Dict[Union[int, str], _GlobalCounter] = dict()

    @classmethod
    def _get_count(cls, thread_id, key, refresh) -> _GlobalCounter:
        counter = _GlobalCounter(thread_id, key, refresh)
        cls._exists[thread_id] = counter
        return counter


class LocalFactory(_CounterFactory):
    _exists: Dict[Union[int, str], _LocalCounter] = dict()

    @classmethod
    def _get_count(cls, thread_id, key, refresh) -> _LocalCounter:
        counter = _LocalCounter(thread_id, key, refresh)
        cls._exists[thread_id] = counter
        return counter
