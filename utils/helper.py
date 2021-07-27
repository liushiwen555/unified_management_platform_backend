import random
import string
import time
from datetime import datetime, timedelta
from typing import Dict

from django.db.models import Model
from django.utils import timezone
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

def random_string(str_length):
    base_str = string.ascii_letters + string.digits
    random_str = ''
    length = len(base_str) - 1
    for i in range(str_length):
        random_str += base_str[random.randint(0, length)]
    return random_str


def bytes2human(n, unit='B'):
    """
    # thanks to the psutil project.
    >>> bytes2human(10000)
    '9.77KB'
    >>> bytes2human(100001221)
    '95.37MB'
    """
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i + 1) * 10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.2f%s%s' % (value, s, unit)
    return '%.2f%s' % (n, unit)


def top(data, key=None, length=8):
    if key:
        data = sorted(data, key=lambda t: float(t[key]), reverse=True)
    else:
        data = sorted(data, key=lambda t: float(t), reverse=True)

    return data[:length]


def model2dict(obj, keys_list=None):
    if isinstance(obj, dict):
        if not keys_list:
            return obj
        else:
            return dict([(key, obj[key]) for key in keys_list])
    elif isinstance(obj, Model):
        if not keys_list:
            keys_list = [f.name for f in obj._meta.get_fields()]
        return dict([(key, getattr(obj, key)) for key in keys_list])
    else:
        if not keys_list:
            return obj
        else:
            return dict([(key, getattr(obj, key)) for key in keys_list])


def get_subclasses(classes, level=0, including_self=False):
    """
        Return the list of all subclasses given class (or list of classes) has.
        Inspired by this question:
        http://stackoverflow.com/questions/3862310/how-can-i-find-all-subclasses-of-a-given-class-in-python
    """
    # for convenience, only one class can can be accepted as argument
    # converting to list if this is the case
    if not isinstance(classes, list):
        classes = [classes]

    if not including_self:
        length = len(classes)
        for i in range(length):
            classes.extend(classes[0].__subclasses__())
            del classes[0]

    if level < len(classes):
        classes += classes[level].__subclasses__()
        return get_subclasses(classes, level + 1, True)
    else:
        return classes


def get_int_choices_range(choices):
    low = high = 0
    for key, _ in choices:
        if key < low:
            low = key
        if key > high:
            high = key

    return low, high


def format_log_time(date_time: datetime = None, format='%Y-%m-%d %H:%M:%S'):
    """
    格式化日志里使用的时间
    :param date_time: 默认是当前时间
    :param format: 默认是年月日 时分秒格式
    :return: 2020-09-23 11:11:11
    """
    if not date_time:
        date_time = timezone.localtime()
    return date_time.strftime(format)


class Timeit:
    def __init__(self):
        self.start = None
        self.end = None

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = time.time()
        print('duration: {}'.format(self.end - self.start))


def get_next_day(current: datetime, tz=None) -> datetime:
    """
    获取下一天
    :param current:当前时间
    :param tz: 时区
    :return: 下一天
    """
    d = current.astimezone().date()
    result = datetime.combine(d + timedelta(days=1), datetime.min.time())
    result = result.astimezone(current.tzinfo)
    if tz:
        result = result.astimezone(tz)
    return result


def get_today(current: datetime = None, tz=None) -> datetime:
    """
    获取当天零点
    :param current:当前时间
    :param tz: 时区
    :return: 当天零点
    """
    if not current:
        current = timezone.now()
    d = current.astimezone().date()
    result = datetime.combine(d, datetime.min.time())
    result = result.astimezone(current.tzinfo)
    if tz:
        result = result.astimezone(tz)
    return result


def get_last_day(current: datetime, tz=None) -> datetime:
    today = get_today(current)
    last = today - timedelta(days=1)
    if tz:
        last = last.astimezone(tz)
    return last


def safe_divide(a, b, precision=0):
    """
    :param a: 被除数
    :param b: 除数
    :param precision: 精度
    :return: 商
    """
    try:
        res = round(a / b, precision)
    except ZeroDivisionError:
        res = 0
    return res


def get_date(current: datetime = None) -> str:
    """
    获取时间的日前
    :return: 日期的字符串
    """
    if not current:
        current = timezone.now()
    return str(timezone.localtime(current).date())


def send_websocket_message(group_name: str, message: Dict, type_='unified_push'):
    """
    向websocket传送数据
    :param group_name: 模块名称，前端按照不同的页面模块建立不同的连接
    :param message: 数据
    :param type_: 推送类型，定义在consumer里
    """
    layer = get_channel_layer()
    message['type'] = type_
    async_to_sync(layer.group_send)(group_name, message)
