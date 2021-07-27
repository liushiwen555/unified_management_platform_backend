import regex as re
from datetime import datetime
from typing import Dict, Optional, Tuple

from django.utils import timezone
from django.db.models import F
from django.db.utils import IntegrityError

from base_app.models import Device
from unified_log.elastic.elastic_model import template_register, FailedLog, BaseDocument
from unified_log.models import LogProcessRule, LogProcessTemplate, LogStatistic
from unified_log.unified_error import LogProcessError, LogPreProcessError
from utils.constants import SYSLOG_FACILITY
from utils.unified_redis import cache as rs
from utils.counter import GlobalFactory
from statistic.tasks import MainViewTask, LogDstIPTopFiveTask

_REGEX_CACHE = {}
# 提取所有syslog默认的基础信息，格式由服务器端的rsyslog配置决定
DEFAULT_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
    r'(?P<hostname>.*?) '
    r'(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) '
    r'(?P<facility>\d{1,2}).*?')


class AbstractRule(object):
    """
    抽象日志规则，用于日志处理，只需要id，日志规则，日志类型即可
    """
    def __init__(self, id: int = None, pattern: str = None,
                 log_type: int = None):
        """
        :param id: 规则id
        :param pattern: 规则内容
        :param log_type: 规则类型，用于决定采用什么什么日志模型 from elastic_model
        """
        self.id = int(id) if id else None
        self.pattern = pattern
        self.log_type = int(log_type) if id else None


class AbstractDevice(object):
    """
    抽象资产，不使用原有的有很多无用字段的设备Model，并且绑定了日志解析模板和日志规则，
    减少多次连表查询
    """
    def __init__(self, name: str, type: str, category: str, id: int,
                 log_status: bool,
                 log_template: str = None, log_rule_pattern: str = None,
                 log_rule_id: int = None, log_rule_type: int = None):
        """
        根据ip，facility定位资产，同时也可以定位到日志的解析规则，所以设备上直接添加解析
        规则的实例
        :param name: 资产名称
        :param type: 资产类型
        :param category: 资产类别
        :param id: 资产id
        :param log_status: 日志监控状态
        :param log_template: 日志解析模板名称
        :param log_rule_pattern: 日志解析规则
        :param log_rule_id: 日志规则id
        :param log_rule_type: 日志规则类型
        """
        self.name = name
        self.type = type
        self.category = category
        self.log_template = log_template
        self.id = int(id)
        self.log_status = True if log_status else False
        self.log_rule = AbstractRule(log_rule_id, log_rule_pattern,
                                     log_rule_type)

    def __str__(self):
        return self.name


class DeviceRuleCache(object):
    """
    资产规则缓存
    一般使用get(ip, facility)方法即可，根据ip和facility查询缓存里的资产，如果没有资产会自动去postgres
    里查询资产，无需单独调用更新缓存的方法
    """
    def __init__(self, timeout: int = 5):
        """
        :param timeout: 缓存过期时间
        """
        self.timeout = timeout
        self.pattern = 'log'    # 缓存内key的模版

    def _key(self, *args) -> str:
        """
        :param args: ip, facility,...
        :return: log-127.0.0.1-auth
        """
        return self.pattern + '-' + '-'.join(args)

    def clean(self):
        """
        清除所有的缓存资产，主要在测试时使用
        """
        keys = rs.keys(self.pattern + '*')
        if keys:
            rs.delete(*keys)

    def get(self, ip: str, facility: str) -> AbstractDevice:
        """
        根据日志里的ip和facility获取资产
        :param ip: 日志头部的ip
        :param facility: 日志头部的facility
        :return: 抽象资产
        """
        res = rs.hgetall(self._key(ip, facility))
        if not res:
            device = Device.objects.select_related(
                'log_template', f'log_template__{facility}').get(ip=ip)
            log_template = device.log_template
            log_rule = getattr(log_template, facility) if log_template else None
            res = self._to_dict(device, device.log_template, log_rule)
            self.set(ip, facility, res)
        device = AbstractDevice(**res)
        return device

    def set(self, ip: str, facility: str, device_data: Dict):
        """
        设置资产缓存，使用hash结构
        :param ip: 资产ip
        :param facility: 日志的facility
        :param device_data: dict化的资产信息
        """
        rs.hmset(self._key(ip, facility), device_data)
        rs.expire(self._key(ip, facility), self.timeout)

    def _to_dict(self, device: Device, log_template: LogProcessTemplate,
                 log_rule: LogProcessRule) -> Dict:
        """
        将orm查询出来的device转换为dict，便于redis存储缓存
        :param device: 查询出的device实例
        :param log_template: 模板实例
        :param log_rule: 日志规则实例
        :return:
        {'name': 'hello', type: 'project', 'log_template': 'morning',
         'log_rule_pattern': '\d{2}'}
        """
        res = {
            'name': device.name,
            'type': device.get_type_display(),
            'category': device.get_category_display(),
            'id': int(device.id),
            'log_status': 1 if device.log_status else 0,
        }
        if log_template:
            res.update({'log_template': log_template.name})
        if log_rule:
            res.update({
                'log_rule_pattern': log_rule.pattern,
                'log_rule_id': int(log_rule.id),
                'log_rule_type': int(log_rule.log_type)
            })
        return res


device_cache = DeviceRuleCache()


class LogProcess(object):
    """
    解析原始日志，提取字段存入elasticsearch
    1. 实例化LogProcess对象，传入原始日志
    2. 解析获取ip，facility，log_time等基本内容，如果这些信息都解析不了，不处理了
    3. 查询日志对应的资产和规则，没有ip和平台资产绑定，也不处理了；如果模板，日志规则没有
    绑定，那就记录一个原始日志
    4. 获取到资产和规则后，对原始日志进行正则解析，解析失败的化记录一个原始日志
    5. 实例化一个Document(Elasticsearch-dsl)的对象
    """
    def __init__(self, log: str, counter=None):
        self.raw_log = log
        self._log: Optional[BaseDocument] = None

        self.ip, self.facility, self.log_time = self.get_ip_facility_log_time()
        self.device = self.get_device()
        self.rule = None
        self.counter = counter or GlobalFactory.get_count(
            refresh=GlobalFactory.LOG_THRESHOLD)

    def get_ip_facility_log_time(self) -> Tuple[str, str, datetime]:
        """
        获取syslog基本的ip，facility，log_time内容，这些格式都是通用的，和日志类型无关
        这里如果解析出错，不保存原始日志，不过一般不会出错
        :return: ip, facility, log_time(datetime object)
        """
        try:
            res = DEFAULT_PATTERN.match(self.raw_log).groupdict()
            ip = res['ip']
            facility = int(res['facility'])
            log_time = datetime.strptime(
                res['timestamp'], '%Y-%m-%d %H:%M:%S').astimezone(
                tz=timezone.utc
            )
        except AttributeError:
            raise LogPreProcessError(f'日志格式不符合标准, log={self.raw_log}')

        try:
            facility = SYSLOG_FACILITY[facility]
        except KeyError:
            raise LogPreProcessError(f'日志的facility异常, facility={facility}')

        return ip, facility, log_time

    def get_device(self) -> AbstractDevice:
        """
        根据IP和facility获取资产，如果日志没有或者没有启用日志监控就不作处理
        :return: device
        """
        try:
            device = device_cache.get(self.ip, self.facility)
            self.device = device
            self.rule = AbstractRule()
        except Device.DoesNotExist:
            raise LogPreProcessError(f'找不到日志对应的资产, ip={self.ip}')
        if not self.device.log_status:
            raise LogPreProcessError(f'资产未启用日志监控, {self.device.name}')
        return device

    def get_rule(self) -> AbstractRule:
        """
        查询资产的对应的日志解析模板，如果没有规则和模板的话，记录一个原始日志
        :return: device, rule
        """
        log_template = self.device.log_template
        if not log_template:
            self.record_raw_log()
            raise LogProcessError(f'资产没有对应的日志模板, ip={self.ip}')
        rule = self.device.log_rule
        if not rule.id:
            self.record_raw_log()
            raise LogProcessError(f'未找到对应的日志解析规则, device={self.device},'
                                  f'template={log_template}')
        return rule

    def process(self) -> Dict:
        """
        处理日志主体内容，如果正则解析失败了，需要记录原始日志
        :return: 解析后的dict的数据
        """
        self.rule = self.get_rule()
        if not _REGEX_CACHE.get(self.rule.id):
            pattern = re.compile(r'{}'.format(self.rule.pattern))
            _REGEX_CACHE[self.rule.id] = pattern
        else:
            pattern = _REGEX_CACHE[self.rule.id]
        try:
            result = pattern.match(self.raw_log).groupdict()
        except AttributeError:
            self.record_raw_log()
            raise LogProcessError(f'日志解析失败, '
                                  f'原始日志: {self.raw_log}, '
                                  f'日志规则: {self.rule.pattern}, ')

        self.log = result   # 实例化Document的对象
        return result

    def save(self):
        """
        保存解析好的日志，没有调用process处理过的日志会在内部调用一此
        """
        if not self._log:
            self.process()
        self._log.save()

    def record_raw_log(self):
        """
        解析失败的情况下，存原始日志，失败日志的status为False
        """
        self._log = FailedLog(
            ip=self.ip,
            dev_id=self.device.id,
            dev_name=self.device.name,
            dev_category=self.device.category,
            dev_type=self.device.type,
            log_time=self.log_time,
            content=self.raw_log,
            timestamp=timezone.now(),
            status=False,
            id=self.get_id(),
        )

    @property
    def log(self) -> BaseDocument:
        return self._log

    @log.setter
    def log(self, result: Dict):
        """
        实例化一个Document对象，规则的log_type决定了要具体调用Document类，根据log_type
        查不到Document，就当解析失败，记录一个原始日志
        :param result: 通过正则表达式解析出的字段
        """
        index_class = template_register.get_index_class(self.rule.log_type)
        if not index_class:
            self.record_raw_log()
            raise LogProcessError(f'不存在日志类型{self.rule.log_type}对应的日志索引')
        if not self._log:
            # 解析成功的日志，status为True
            self._log = index_class(
                dev_id=self.device.id,
                dev_name=self.device.name,
                dev_type=self.device.type,
                dev_category=self.device.category,
                log_time=self.log_time,
                content=self.raw_log,
                status=True,
                id=self.get_id(),
                **result,
            )

    def update_log_statistic_info(self):
        """
        更新日志的统计信息，这里为了避免加锁以及get_or_create冲突的影响，特意做了判断
        如果存在，直接更新
        否则是创建新的logstatistic，如果重复的话会报错，直接走更新流程
        """
        exist = LogStatistic.objects.filter(device_id=self.device.id).exists()
        if not exist:
            try:
                l = LogStatistic(device_id=self.device.id, total=1)
                l.save()
                return
            except IntegrityError:
                pass
        LogStatistic.objects.filter(device_id=self.device.id).update(
            total=F('total')+1, update_time=timezone.now(),
        )

    def get_id(self):
        """
        自定义的id，主要用于search_after
        :return: 返回计数器的信息，主要是由计数器id+计数器的结果
        """
        self.counter.add(1)
        return str(self.counter)
