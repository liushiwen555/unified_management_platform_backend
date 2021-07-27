from django.urls import resolve

from base_app.models import Device
from snmp.models import SNMPTemplate
from log.log_content.log_generator import LogGenerator, LogConfig, HookAbstract
from log.models import UnifiedForumLog


snmp_config = LogConfig()


class SNMPLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_KNOWLEDGE,
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION


@snmp_config.register('snmptemplate-detail', ['DELETE', 'PUT'],
                      additional_info=True)
@snmp_config.register('snmptemplate-list', ['POST'])
class SNMPTemplateLogGenerator(SNMPLogMixin, LogGenerator):
    """
    记录SNMP模板的增删改
    日志格式：
    添加了【SNMP模板ID】-【SNMP模板名称】
    删除了【SNMP模板ID】-【SNMP模板名称】
    修改了【SNMP模板ID】-【SNMP模板名称】
    """
    content_template = '{method}性能监控模板【{name}】, {result}'
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
        添加了 4 - SNMP1
        删除了 4 - SNMP1
        修改了 4 - SNMP1
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


@snmp_config.register('device-manage-snmp-setting', ['PUT'])
class SNMPSettingLogGenerator9(SNMPLogMixin, LogGenerator):
    """
    修改资产的SNMP设置

    """
    data_template = {
        'type': UnifiedForumLog.TYPE_ASSETS
    }

    content_template = '设置【{id} - {name}】的性能监控, {result}'

    def get_content(self):
        return self.content_template.format(
            id=self.get_asset_id(),
            name=self.get_asset_name(),
            result=self.resp_result
        )

    def get_asset_id(self) -> int:
        return resolve(self.request.path).kwargs.get('pk')

    def get_asset_name(self) -> str:
        device = Device.objects.get(id=self.get_asset_id())
        return device.name
