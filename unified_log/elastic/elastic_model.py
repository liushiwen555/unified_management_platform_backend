from typing import List, Dict, Type
from datetime import datetime

from django.utils import timezone
from django.conf import settings
from elasticsearch_dsl import Document, Date, Keyword, Ip, Integer, Text, Boolean
from elasticsearch_dsl.document import META_FIELDS

from unified_log.models import *
from unified_log.elastic.elastic_client import client


def get_all_fields(document: Type[Document]) -> set:
    """
    获取Document里定义了哪些字段
    :param document: 模型类
    :return: 字段集合
    """
    fields = set()
    for field, field_type, _ in document._ObjectBase__list_fields():
        fields.add(field)
    return fields


class BaseDocument(Document):
    def __init__(self, meta=None, **kwargs):
        meta = meta or {}
        fields = get_all_fields(self.__class__)
        for k in list(kwargs):
            if k.startswith("_") and k[1:] in META_FIELDS:
                meta[k] = kwargs.pop(k)
                continue
            if k not in fields:
                # 过滤掉不属于这个document的字段
                kwargs.pop(k)
            else:
                kwargs[k] = kwargs[k] if kwargs[k] != '' else None
        kwargs['timestamp'] = timezone.now()
        super(BaseDocument, self).__init__(meta, **kwargs)

    prefix = 'test-' if settings.TEST else ''

    ip = Ip()
    src_ip = Ip()
    src_port = Integer()
    dst_ip = Ip()
    dst_port = Integer()
    dev_id = Integer()
    dev_name = Keyword()
    dev_type = Keyword()
    dev_category = Keyword()
    log_time = Date(default_timezone='UTC')
    timestamp = Date(default_timezone='UTC')
    content = Text()
    status = Boolean()
    id = Keyword()

    class Index:
        key = None
        name = 'log'
        settings = {
            'default_pipeline': 'add_duplicate_id',
        }

    @classmethod
    def index_name(cls):
        return cls.prefix + cls.Index.name

    @classmethod
    def index_pattern(cls):
        return cls.prefix + cls.Index.name + '*'

    def _date_index(self):
        return timezone.localtime().strftime(f'{self.index_name()}-%Y%m%d')

    @classmethod
    def search(cls, using=None, index=None):
        return super().search(using, index=cls.index_pattern())

    def save(self, **kwargs):
        kwargs['index'] = self._date_index()
        return super().save(**kwargs)

    def to_dict(self, include_meta=False, skip_empty=True):
        meta = super().to_dict(include_meta, skip_empty)
        if not include_meta:
            return meta
        meta['_index'] = self._date_index()
        return meta

    @classmethod
    def search_with_scroll(cls, body, scroll_time='2m'):
        return client.search_with_scroll(cls.index_pattern(), body, scroll_time)

    @classmethod
    def scroll(cls, scroll_id, scroll_time='2m'):
        return client.scroll(scroll_id, scroll_time)

    @classmethod
    def search_after(cls, body: Dict, sort=None, after=None):
        """
        适用于滚动加载查询日志的优化的方式
        :param body: 查询内容，包括条件，size
        :param sort: 排序字段，默认使用timestamp和id
        :param after: 上一次查询结果的最后一条数据的sort字段
        :return: 新的查询结果
        """
        if not sort:
            sort = [
                {'timestamp': 'desc'},
                {'id': 'desc'},
            ]
        body.update({'sort': sort})
        return client.search_after(cls.index_pattern(), body, after)


class TemplateRegister:
    def __init__(self):
        self._documents: List[BaseDocument] = []
        self._dict: Dict[int, BaseDocument] = {}

    def register(self, cls: BaseDocument):
        self._documents.append(cls)
        self._dict[cls.Index.key] = cls
        return cls

    def save_template(self):
        for cls in self._documents:
            log = cls._index.as_template(cls.index_name(),
                                         pattern=cls.index_pattern(),
                                         order=0)
            log.save()

    def get_index_class(self, log_type: int) -> BaseDocument:
        return self._dict.get(log_type)


template_register = TemplateRegister()


@template_register.register
class FailedLog(BaseDocument):
    class Index:
        name = 'log-fail'
        key = -1


@template_register.register
class AuthLog(BaseDocument):

    class Index:
        name = 'log-auth'
        key = LOG_AUTH


@template_register.register
class AuthPrivLog(BaseDocument):
    class Index:
        name = 'log-privauth'
        key = LOG_AUTHPRIV


@template_register.register
class KernLog(BaseDocument):
    in_network = Keyword()
    out_network = Keyword()
    src_mac = Keyword()
    protocol = Keyword()

    class Index:
        name = 'log-kernel'
        key = LOG_KERNEL


@template_register.register
class DaemonLog(BaseDocument):
    protocol = Keyword()

    class Index:
        name = 'log-daemon'
        key = LOG_DAEMON


@template_register.register
class CronLog(BaseDocument):
    class Index:
        name = 'log-cron'
        key = LOG_CRON


@template_register.register
class SysLog(BaseDocument):
    class Index:
        name = 'log-syslog'
        key = LOG_SYSLOG


@template_register.register
class AuditLog(BaseDocument):
    def __init__(self, meta=None, **kwargs):
        kwargs['audit_date'] = datetime.strptime(kwargs['audit_date'],
                                                 '%Y/%m/%d %H:%M:%S')
        super().__init__(meta, **kwargs)

    src_mac = Keyword()
    dst_mac = Keyword()
    device_id = Integer()
    audit_date = Date()
    device_name = Keyword()
    audit_logtype = Integer()
    audit_pri = Integer()
    mod = Keyword()
    protocol = Keyword()
    audit_msg = Text(analyzer='ik_max_word', search_analyzer='ik_smart')

    class Index:
        name = 'log-audit-alarm'
        key = LOG_AUDIT_ALARM


@template_register.register
class NginxLog(BaseDocument):
    def __init__(self, meta=None, **kwargs):
        try:
            kwargs['nginx_date'] = datetime.strptime(
                kwargs['nginx_date'], '%d/%b/%Y:%H:%M:%S %z',
            )
        except Exception:
            kwargs['nginx_date'] = datetime.strptime(
                kwargs['nginx_date'], '%Y/%m/%d %H:%M:%S',
            )
        super().__init__(meta, **kwargs)

    remote_user = Keyword()
    nginx_date = Date()
    request = Text()
    status_code = Integer()
    body_bytes_sent = Integer()
    http_referer = Text()
    http_user_agent = Text()
    upstream = Text()
    host = Text()

    class Index:
        name = 'log-nginx'
        key = LOG_NGINX


@template_register.register
class MailLog(BaseDocument):
    class Index:
        name = 'log-mail'
        key = LOG_MAIL


@template_register.register
class FTPLog(BaseDocument):
    class Index:
        name = 'log-ftp'
        key = LOG_FTP


@template_register.register
class HuaWeiSwitchLog(BaseDocument):
    class Index:
        name = 'log-switch-huawei'
        key = LOG_SWITCH_HUAWEI

    device_name = Keyword()
    vpn_name = Keyword()
    user = Keyword()
    auth_method = Keyword()
    command = Text()


@template_register.register
class PostgresLog(BaseDocument):
    class Index:
        name = 'log-database-postgres'
        key = LOG_DATABASE_POSTGRESQL

    sql = Text()
    error = Text()


@template_register.register
class AsusRouterLog(BaseDocument):
    class Index:
        name = 'log-router-asus'
        key = LOG_ROUTER_ASUS

    device_name = Keyword()
    src_mac = Keyword()
    dst_mac = Keyword()
    DHCP = Keyword()
    requested_ip = Ip()
    status_code = Integer()
    in_network = Keyword()
    reason = Text()
    function = Text()
    source = Text()


@template_register.register
class WindowsLog(BaseDocument):
    application = Text()
    function = Text()
    source = Text()
    sid = Keyword()

    class Index:
        name = 'log-windows'
        key = LOG_WINDOWS


template_register.save_template()
