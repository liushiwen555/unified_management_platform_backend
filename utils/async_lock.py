from utils.unified_redis import rs
import time


class ForceDropError(Exception):
    def __str__(self):
        return f'无法获取到锁'


class RedisLock(object):
    def __init__(self, key: str, expired_time: int = 1, delay: int = 0,
                 force_drop: bool = False):
        """
        :param key: 锁的key
        :param expired_time: 锁强制释放时间
        :param force_drop: 当没有获取锁时，是否强制结束锁内的任务执行
        :param delay: 是否要延迟释放锁，延迟释放时设置多久的时长
        """
        self.key = key
        self.expired_time = expired_time
        self.force_drop = force_drop
        self.delay = delay

    def __enter__(self):
        self._acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._release()

    def _have_acquired(self):
        return rs.set(self.key, 1, ex=self.expired_time, nx=True)

    def _acquire(self):
        curr = 0
        while curr <= self.expired_time:
            if self._have_acquired():
                return True
            else:
                if self.force_drop:
                    # 抛出强制放弃的错误，让调用方处理后续的内容
                    raise ForceDropError()
            curr += 0.2
            time.sleep(0.2)

    def _release(self):
        if self.delay:
            rs.setex(self.key, self.delay, 1)
        else:
            rs.delete(self.key)
