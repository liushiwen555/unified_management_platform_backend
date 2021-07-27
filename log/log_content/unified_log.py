"""
日志管理的操作日志
"""
from django.urls import resolve

from base_app.models import Device
from log.log_content.log_generator import LogGenerator, LogConfig, HookAbstract
from log.models import UnifiedForumLog

unified_log_config = LogConfig()


class UnifiedLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_KNOWLEDGE,
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION


@unified_log_config.register('log-template-list', ['POST'])
@unified_log_config.register('log-template-detail', ['PUT', 'DELETE'],
                             additional_info=True)
class LogTemplateGenerator(UnifiedLogMixin, LogGenerator, HookAbstract):
    """
    记录日志解析模板的增删改
    日志格式：
    添加了【日志解析模板ID】-【日志解析模板名称】
    删除了【日志解析模板ID】-【日志解析模板名称】
    修改了【日志解析模板ID】-【日志解析模板名称】
    """
    content_template = '{method}日志监控模板【{name}】, {result}'
    method_map = {
        'POST': '添加',
        'DELETE': '删除',
        'PUT': '编辑',
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.item = kwargs.get('item')  # 删除资产的时候会用到它

    def get_content(self) -> str:
        """
        :return:
        添加了 4 - Template1
        删除了 4 - Template1
        修改了 4 - Template1
        """
        content = self.content_template.format(
            method=self.method_map[self.method],
            id=self.get_template_id(),
            name=self.get_template_name(),
            result=self.resp_result,
        )
        return content

    def get_template_id(self) -> int:
        if self.method in ['DELETE', 'PUT']:
            return resolve(self.request.path).kwargs.get('pk')
        else:
            return self.response.data.get('id')

    def get_template_name(self) -> str:
        if self.method in ['PUT', 'POST']:
            return self.request_body['name']
        else:
            return self.item.name if self.item else None

    @classmethod
    def get_previous(cls, request):
        resolved = resolve(request.path)
        pk = resolved.kwargs.get('pk')
        item = resolved.func.cls.queryset.get(pk=pk)

        return {'item': item}


@unified_log_config.register('device-manage-log-setting', 'PUT')
class UnifiedLogSettingLogGenerator(LogGenerator):
    data_template = {
        'type': UnifiedForumLog.TYPE_ASSETS,
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION

    content_template = '设置【{id}-{name}】的日志监控'

    def get_content(self):
        pk = resolve(self.request.path).kwargs.get('pk')
        device = Device.objects.get(pk=pk)
        return self.content_template.format(
            id=device.id, name=device.name
        )
