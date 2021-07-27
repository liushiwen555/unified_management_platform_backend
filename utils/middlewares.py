import json
import logging
import time
from json import JSONDecodeError

from django.contrib.auth import get_user_model
from django.contrib.auth import logout
from django.http.response import JsonResponse
from django.urls import reverse
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed

from log.log_config import ModelLog
from log.log_content import additional_before_delete
from log.models import UnifiedForumLog
from setting.models import Setting
from utils.async_lock import RedisLock, ForceDropError
from utils.core.authentication import EncryptedTokenAuthentication
from utils.core.exceptions import CustomError
from utils.unified_redis import rs

User = get_user_model()
logger = logging.getLogger(__name__)

MACHINE_PULL = 'HTTP_MACHINE_PULL'
SMM_MACHINE = 'HTTP_SMM_MACHINE'
MANAGE_HEADER = 'HTTP_SECRET'
LOCAL_IP = '127.0.0.1'
ANONYMOUS_NAME = 'anonymous'
LAST_TOUCH = 'last_touch'
LOGIN_PATH = reverse('user-login')

# redis key names
REDIS_PLATFORM_IP = 'platform_ip'
REDIS_PLATFORM_SECRET = 'platform_secret'
REDIS_PLATFORM_VALID = 'platform_valid'
REDIS_ACTIVATION_VALID_UNTIL = 'valid_until'
REDIS_ALLOWED_IP = 'allowed_ip'
REDIS_INACTIVITY_TIMEOUT = 'inactivity_timeout'


class CheckIPAndTimeoutMiddleware(object):
    """
    自动登出无操作的用户
    排除来自本地的用户， 排除带有`MACHINE-PULL`请求头的 request， `MACHINE-PULL`用于前端轮询时携带的请求头。
    对于普通请求， 检测session 中的`last_touch`时间戳和当前时间戳的时间差， 高于 settings 中的INACTIVITY_TIMEOUT设定时间时自动
    登出， 并且返回302状态码， 携带 json 数据， 返回的头部中不携带 location信息。
    """

    def __init__(self, get_response):
        setting, created = Setting.objects.get_or_create(id=1)
        self.get_response = get_response

        # self.inactivity_timeout = setting.login_timeout_duration * 60
        # self.ip_limit_enable = setting.ip_limit_enable
        # self.allowed_ip = setting.allowed_ip
        # self.all_remote_ip_limit_enable = setting.all_remote_ip_limit_enable

        # 参考审计的验证方式
        rs.set(REDIS_INACTIVITY_TIMEOUT, setting.login_timeout_duration * 60)
        rs.delete(REDIS_ALLOWED_IP)
        if setting.ip_limit_enable:
            rs.sadd(REDIS_ALLOWED_IP, *set(setting.allowed_ip))

    def process_view(self, request, view_func, view_args, view_kwargs):
        remote_addr = request.META['REMOTE_ADDR']
        machine_pull = request.META.get(MACHINE_PULL)
        manage_header = request.META.get(MANAGE_HEADER)
        smm_machine = request.META.get(SMM_MACHINE)

        # if remote_addr == LOCAL_IP or machine_pull or manage_header:
        #     return

        session = request.session
        # has_token = request.META.get('HTTP_AUTHORIZATION')
        # 从 Token 中取出 user
        # auth = TokenAuthentication()
        auth = EncryptedTokenAuthentication()

        try:
            user_auth_tuple = auth.authenticate(request)
            if user_auth_tuple is None:
                user = None
            else:
                user, auth = user_auth_tuple
        except AuthenticationFailed as exc:
            return JsonResponse(status=401, data={'detail': exc.detail})

        if self.ip_has_been_banned(remote_addr):
            return JsonResponse(
                data=CustomError(error_code=CustomError.IP_LIMIT_ERROR).detail,
                status=CustomError.status_code
            )
        # 禁止所有用户登录
        setting, created = Setting.objects.get_or_create(id=1)

        # 旧版综管方法
        # if self.ip_limit_enable and (remote_addr not in self.allowed_ip):
        #     UnifiedForumLog.objects.create(
        #         ip=remote_addr,
        #         type=UnifiedForumLog.TYPE_PLATFORM_OPERATION,
        #         result=False,
        #         # user=user,
        #         category=UnifiedForumLog.CATEGORY_MANAGEMENT,
        #         content='IP {}未在允许列表中，访问失败'.format(remote_addr)
        #     )
        #     return JsonResponse(status=499, data={'error': CustomError.IP_LIMIT_ERROR})
        if not user:
            # 对未登录的用户无处理
            return
        request.user = user
        request._user = user
        # TODO 此处ssm_machine的含义位置，但是逻辑和下面的一样，先注释掉，启用下面的逻辑
        # if not smm_machine and request.path != LOGIN_PATH:
        #     if LAST_TOUCH in session and time.time() - session[LAST_TOUCH] > int(rs.get(REDIS_INACTIVITY_TIMEOUT)):
        #         logout(request)
        #         # record_log(1, user.username, remote_addr, '长时间无操作自动退出')
        #         user.auth_token.save()  # 重新生成token
        #         rs.delete(user.username)  # 清空身份认证时用于加密token的盐，参照utils.core.authentication.EncryptedTokenAuthentication
        #         return JsonResponse(status=499, data={'error': CustomError.AUTO_LOGOUT_ERROR})

        # 超时登出
        if request.path != LOGIN_PATH:
            inactivity_timeout = int(rs.get(REDIS_INACTIVITY_TIMEOUT))
            if (LAST_TOUCH in session and
                    time.time() - session[LAST_TOUCH] > inactivity_timeout):
                request.user = user
                logout(request)
                self.login_overtime(user, remote_addr, inactivity_timeout)
                return JsonResponse(
                    CustomError(error_code=CustomError.AUTO_LOGOUT_ERROR).detail,
                    status=CustomError.status_code)
            session[LAST_TOUCH] = time.time()

    def login_overtime(self, user: User, ip: str, inactivity_timeout: int):
        """
        超时登出的日志记录，为避免重复记录，增加锁
        :param user: 用户
        :param ip: 源ip
        :param inactivity_timeout: 未操作的时长
        """
        if not user:
            return
        try:
            with RedisLock('login_overtime', force_drop=True, delay=1):
                UnifiedForumLog.objects.create(
                    user=user.username,
                    group=user.group.name,
                    ip=ip,
                    type=UnifiedForumLog.TYPE_LOGOUT,
                    category=UnifiedForumLog.CATEGORY_LOGIN_LOGOUT,
                    content='未进行操作达{}分钟，超时自动登出综合管理平台'.format(
                        inactivity_timeout / 60)
                )
                user.auth_token.save()
        except ForceDropError:
            pass

    def ip_has_been_banned(self, remote_addr: str):
        """
        判断用户ip是不是被禁止访问
        :param remote_addr: 用户ip
        :return: 如果用户ip被禁，需要记录日志
        """
        if rs.exists(REDIS_ALLOWED_IP) and not rs.sismember(
                REDIS_ALLOWED_IP, remote_addr
        ):
            UnifiedForumLog.objects.create(
                ip=remote_addr,
                type=UnifiedForumLog.TYPE_LOGIN,
                result=False,
                category=UnifiedForumLog.CATEGORY_LOGIN_LOGOUT,
                content='IP {}未在允许列表中，访问失败'.format(remote_addr)
            )
            return True
        return False

    def __call__(self, request):
        response = self.get_response(request)
        return response


class SetRemoteAddressMiddleware(object):
    """
    这个中间件提供了从 nginx 反向代理中提取真实 ip，并将其在 META 中设置。
    需要在 nginx 中提供以下设置
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        x_real_ip = request.META.get('HTTP_X_REAL_IP', None)
        if x_real_ip:
            x_real_ip = x_real_ip.split(',')[0].strip()
            request.META['REMOTE_ADDR'] = x_real_ip

        response = self.get_response(request)
        return response


class ErrorLogMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.

        response = self.get_response(request)

        # Code to be executed for each request/response after
        # the view is called.
        if not status.is_success(response.status_code):
            if request.method == 'GET' or request.method == 'DELETE':
                logger.warning("query params :" + request.META['QUERY_STRING'])
            else:
                pass
            logger.error(response.content)

        return response


class LogModelMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response
        self.model_log = ModelLog()
        # One-time configuration and initialization.

    def _check_body(self, request):
        body = request.body
        for k, v in request.FILES.items():
            if v is not None:
                return False, None
        return True, body

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        # self.need_log = self.model_log.need_log(request.resolver_match.url_name, request.method)
        self.copy_body = None
        unsafe_method = request.method in ['POST', 'PUT', 'PATCH']
        enable_to_copy_and_body = self._check_body(request)
        enable_to_copy, request_body = enable_to_copy_and_body

        if unsafe_method and enable_to_copy:
            try:
                self.copy_body = json.loads(request_body, encoding='utf-8')
            except JSONDecodeError as e:
                self.copy_body = None

        kwargs = additional_before_delete.get_additional_info(request)
        response = self.get_response(request)
        # Code to be executed for each request/response after
        # the view is called.
        result = status.is_success(response.status_code)
        # print(request.resolver_match.url_name)
        # print(request.resolver_match.kwargs)
        # print(self.copy_body)
        self.model_log.log(request, self.copy_body, result, response, **kwargs)
        return response

# class TestMiddleware:
#     """
#     自动登出无操作的用户
#     排除来自本地的用户， 排除带有`MACHINE-PULL`请求头的 request， `MACHINE-PULL`用于前端轮询时携带的请求头。
#     对于普通请求， 检测session 中的`last_touch`时间戳和当前时间戳的时间差， 高于 settings 中的INACTIVITY_TIMEOUT设定时间时自动
#     登出， 并且返回302状态码， 携带 json 数据， 返回的头部中不携带 location信息。
#     """
#     def __init__(self, get_response):
#         self.get_response = get_response
#         # self.inactivity_timeout = settings.INACTIVITY_TIMEOUT
#
#     def process_view(self, request, view_func, view_args, view_kwargs):
#         view = get_class(view_func.__module__, view_func.__name__)
#         try:
#             print(view.get_object())
#         except Exception as e:
#             print(str(e))
#
#     def __call__(self, request):
#         response = self.get_response(request)
#         return response
#
#
# def get_class(module_name, cls_name):
#     try:
#         module = importlib.import_module(module_name)
#     except ImportError:
#         raise ImportError('Invalid class path: {}'.format(module_name))
#     try:
#         cls = getattr(module, cls_name)
#     except AttributeError:
#         raise ImportError('Invalid class name: {}'.format(cls_name))
#     else:
#         return cls
