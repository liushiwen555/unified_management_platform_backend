"""
安全中心日志
"""
from typing import Optional

from django.urls import resolve

from log.log_content.log_generator import LogGenerator, LogConfig, HookAbstract
from log.models import UnifiedForumLog

security_config = LogConfig()


class SecurityLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_SECURITY,
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION


@security_config.register('download-report-log', 'get')
@security_config.register('report-log-list', 'post')
@security_config.register('report-log-detail', 'delete', additional_info=True)
class SecurityLogGenerator(SecurityLogMixin, LogGenerator, HookAbstract):
    """
    记录安全中心报表中心操作日志
    日志格式：
    添加了【ID】号报表
    下载了【ID】号报表
    删除了【ID】号报表
    """
    content_template = '{method}了 {id} 号报表, {result}'
    method_map = {
        'GET': '下载',
        'POST': '添加',
        'DELETE': '删除',
    }

    def get_content(self) -> str:
        """
        组合日志详细内容
        :return:
        添加了【ID】号报表
        下载了【ID】号报表
        删除了【ID】号报表
        """
        content = self.content_template.format(
            method=self.method_map[self.method],
            id=self.get_report_id(),
            result=self.resp_result,
        )
        return content

    def get_report_id(self) -> Optional[int]:
        """
        从path或者响应里获取报表的id
        :return: 报表的ID
        """
        if self.method in ['GET', 'DELETE']:
            return resolve(self.request.path).kwargs.get('pk')
        else:
            return self.response.data.get('id')

    @classmethod
    def get_previous(cls, request):
        resolved = resolve(request.path)
        pk = resolved.kwargs.get('pk')
        item = resolved.func.cls.queryset.get(pk=pk)

        return {'item': item}
