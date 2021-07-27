import threading
from abc import ABC, abstractmethod
from typing import Union, List, Dict

from django.contrib.auth import get_user_model
from django.db.models import Model
from django.urls import resolve
from rest_framework.response import Response

from log.models import UnifiedForumLog


User = get_user_model()


class HookAbstract(ABC):
    @classmethod
    @abstractmethod
    def get_previous(cls, request):
        pass


class LogGenerator(ABC):
    content_template = None
    data_template = None
    log_cls = UnifiedForumLog
    log_category = ''

    def __init__(self, request, request_body: Dict, result: bool,
                 response: Response, *args, **kwargs):
        """
        :param request:
        :param request_body: 请求body
        :param result: 请求是否处理成功
        :param response:
        :param args:
        :param kwargs: 额外的附加信息，比如删除资源时需提前获取资源的信息等
        """
        self.request = request
        self.response = response
        self.method = request.method
        self.user = request.user
        self.ip = request.META['REMOTE_ADDR']
        self.request_body = request_body
        self.result = result
        self._check_template()
        self.content = ''

    @abstractmethod
    def get_content(self):
        pass

    def get_group(self) -> str:
        if self.user.is_anonymous:
            return ''

        return self.user.group.name

    def get_username(self) -> str:
        return self.user.username or 'AnonymousUser'

    def get_data(self):
        self.content = self.get_content()
        self.data_template['result'] = self.result
        self.data_template['user'] = self.get_username()
        self.data_template['group'] = self.get_group()
        self.data_template['content'] = self.content
        self.data_template['category'] = self.log_category
        self.data_template['ip'] = self.ip
        return self.data_template

    def generate_log(self):
        self.log_cls.objects.create(**self.get_data())

    def _check_template(self):
        assert self.data_template is not None, (
                "'%s' should include a `data_template` attribute, "
                % self.__class__.__name__
        )
        assert self.content_template is not None, (
                "'%s' should include a `content_template` attribute, "
                % self.__class__.__name__
        )

    @property
    def resp_result(self):
        return '成功' if self.result else '失败'


class LogConfig(object):
    _instance = None
    _init_flag = False

    def __init__(self):
        if not LogConfig._init_flag:
            # 只初始化一次log_config,避免被覆盖
            self._log_config = {}
            LogConfig._init_flag = True

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with threading.Lock():
                if not cls._instance:
                    cls._instance = super().__new__(cls, *args, **kwargs)
        return cls._instance

    def register(self, url_name: str, methods: Union[str, List[str]],
                 additional_info: bool = False):
        """
        提供class的装饰器，使用格式为
        @register('device-list', ['get', 'post'])
        class LogGenerator():
            pass
        :param url_name: 路由名称以及对应的method
        :param methods: 单个HTTP方法名或HTTP方法列表
        :param additional_info: 是否需要提前获取修改的对象
        """

        def wrapper(cls):
            if isinstance(methods, str):
                method_list = [methods]
            else:
                method_list = methods
            for method in method_list:
                method = method.upper()
                if self._log_config.get(url_name):
                    self._log_config[url_name][method] = cls
                else:
                    self._log_config[url_name] = {method: cls}
                if method == 'DELETE' or additional_info:
                    additional_before_delete.register(url_name, method, cls)

            return cls

        return wrapper

    def get_config(self) -> Dict[str, Dict[str, LogGenerator]]:
        """
        返回路由，方法和日志类的配置
        :return:
        {
            'device-list':
                {'GET': LogGenerator,
                'POST': LogGenerator},
        }
        """
        return self._log_config


log_config = LogConfig()


class AdditionalInfoBeforeDelete(object):
    """
    删除资源的时候，在处理日志的时候，是无法得到被删除的资源的信息，只能提前获取
    """
    _config = {}

    @classmethod
    def register(cls, url_name: str, method: str, hook: HookAbstract = None):
        """
        注册需要提前获取信息日志类
        :param url_name: 正常的urlname，可以用reverse反向解析
        :param method: http方法
        :param hook: 钩子类，也就是日志处理的类，如果传了这个类，就可以使用类里提供的
        get_previous方法获取信息,hook必须继承自HookAbstract接口
        """
        target = hook or True
        if cls._config.get(url_name):
            cls._config[url_name][method] = target
        else:
            cls._config[url_name] = {method: target}

    @classmethod
    def get_additional_info(cls, request) -> Dict[str, Model]:
        """
        在中间件中使用，获取删除前的资源的信息
        :param request:
        :return: {'item': <Device: 48 交换机 通信资产>, ...}
        """
        resolved = resolve(request.path)
        url_name = resolved.url_name
        if not (cls._config.get(url_name) and cls._config[url_name].get(request.method)):
            return {}
        hook = cls._config[url_name][request.method]
        return hook.get_previous(request)


additional_before_delete = AdditionalInfoBeforeDelete()
