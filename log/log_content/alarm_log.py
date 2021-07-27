"""
安全事件+安全威胁管理日志
"""
from django.urls import resolve

from log.log_content.log_generator import LogGenerator, LogConfig, HookAbstract
from log.models import UnifiedForumLog

alarm_config = LogConfig()


class AlarmLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_ALARM,
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION


@alarm_config.register('resolve-alert', 'put')
class AlarmLogGenerator(AlarmLogMixin, LogGenerator):
    """
    记录安全威胁的操作日志
    日志格式：
    处理了【ID】了{}号安全威胁
    """
    content_template = '{method}了 {id} 号安全威胁, {result}'
    method_map = {
        'PUT': '处理'
    }

    def get_content(self):
        """
        组合日志详细内容
        :return:
        处理了4号安全威胁
        """
        content = self.content_template.format(
            method=self.method_map[self.method],
            id=self.get_alarm_id(),
            result=self.resp_result,
        )
        return content

    def get_alarm_id(self):
        return resolve(self.request.path).kwargs.get('pk')


@alarm_config.register('batch-resolve-alert', 'put')
class AlarmBatchLogGenerator(AlarmLogMixin, LogGenerator):
    """
    记录安全威胁管理的操作日志
    日志格式：
    批量处理了【ID】号等【X】条安全威胁
    """
    content_template = '{method}了 {id} 号等{count}条安全威胁, {result}'
    method_map = {
        'PUT': '批量处理'
    }

    def get_content(self):
        """
        :return: 批量处理了4号等25条安全威胁
        """
        content = self.content_template.format(
            method=self.method_map[self.method],
            id=self.request_body['ids'][0],
            count=len(self.request_body['ids']),
            result=self.resp_result,
        )
        return content


@alarm_config.register('resolve-all-alert', 'put')
class AlarmAllLogGenerator(AlarmLogMixin, LogGenerator):
    """
    记录安全威胁管理的操作日志
    日志格式：
    批量处理了 20 号等30条安全威胁
    """
    content_template = '{method}了 {id} 号等{count}条安全威胁, {result}'
    method_map = {
        'PUT': '批量处理'
    }

    def get_content(self):
        """
        :return: 批量处理了 20 号等30条安全威胁
        """
        content = self.content_template.format(
            method=self.method_map[self.method],
            id=self.response.data['first_id'],
            count=self.response.data['count'],
            result=self.resp_result,
        )
        return content


@alarm_config.register('resolve-security', 'put')
class SecurityEventLogGenerator(AlarmLogGenerator):
    """
    记录安全威胁的操作日志
    日志格式：
    处理了【ID】了{}号安全事件
    """
    content_template = '{method}了 {id} 号安全事件, {result}'


@alarm_config.register('batch-resolve-security', 'put')
class SecurityBatchLogGenerator(AlarmBatchLogGenerator):
    """
    记录安全事件管理的操作日志
    日志格式：
    批量处理了【ID】号等【X】条安全事件
    """
    content_template = '{method}了 {id} 号等{count}条安全事件, {result}'


@alarm_config.register('resolve-all-security', 'put')
class SecurityAllLogGenerator(AlarmAllLogGenerator):
    """
    记录安全事件管理的操作日志
    日志格式：
    批量处理了【ID】号等【X】条安全事件
    """
    content_template = '{method}了 {id} 号等{count}条安全事件, {result}'
