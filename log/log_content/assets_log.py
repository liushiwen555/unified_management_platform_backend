"""
资产管理日志
"""
from django.urls import resolve

from base_app.models import Device
from log.log_content.log_generator import LogGenerator, LogConfig, HookAbstract
from log.models import UnifiedForumLog, DeviceAllAlert
from base_app.filters import DeviceFilter
from base_app.serializers import DeviceFilterSerializer
from log.security_event import AssetsEventLog

assets_config = LogConfig()


class AssetsLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_ASSETS,
    }
    log_category = UnifiedForumLog.CATEGORY_OPERATION


@assets_config.register('device-manage-detail', ['DELETE', 'PUT'])
@assets_config.register('device-manage-list', ['POST'])
class AssetsLogGenerator(AssetsLogMixin, LogGenerator, HookAbstract):
    """
    记录资产的增删改
    日志格式：
    添加了【资产ID】-【资产名称】
    删除了【资产ID】-【资产名称】
    修改了【资产ID】-【资产名称】

    删除和修改资产还需要生成告警
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.item = kwargs.get('item')  # 删除资产的时候会用到它

    content_template = '{method}【{id} - {name}】, {result}'
    method_map = {
        'POST': '添加',
        'DELETE': '删除',
        'PUT': '编辑',
    }
    alert_desc_template = '{user}{method}【{id} - {name}】'

    def get_content(self) -> str:
        """
        :return:
        添加了 4 - 木链审计
        删除了 4 - 木链审计
        编辑了 4 - 木链审计
        """
        content = self.content_template.format(
            method=self.method_map[self.method],
            id=self.get_asset_id(),
            name=self.get_asset_name(),
            result=self.resp_result,
        )
        return content

    def get_asset_id(self) -> int:
        if self.method in ['DELETE', 'PUT']:
            return resolve(self.request.path).kwargs.get('pk')
        else:
            return self.response.data.get('id')

    def get_asset_name(self) -> str:
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

    def generate_log(self):
        if self.method == 'DELETE':
            delete_log = AssetsEventLog(device_id=self.get_asset_id(),
                                        device_name=self.get_asset_name())
            delete_log.generate()
        return super().generate_log()


@assets_config.register('device-batch', 'PUT')
class AssetsStatusGenerator(AssetsLogMixin, LogGenerator):
    """
    记录资产的IP,MAC绑定
    日志格式：
    批量修改 【】 - 【】等【】个资产IP/MAC绑定状态为【启用/停用】
    """
    content_template = {
        'ip_mac_bond': ('批量编辑【{id} - {name}】等{count}个资产IP/MAC绑定为{status},'
                        ' {result}'),
        'monitor': ('批量编辑【{id} - {name}】等{count}个资产性能监控为{status},'
                    ' {result}'),
        'log_status': ('批量编辑【{id} - {name}】等{count}个资产日志监控为{status},'
                       ' {result}'),
        'responsible_user': ('批量编辑【{id} - {name}】等{count}个资产安全负责人为'
                             '{status}, {result}'),
        'location': ('批量编辑【{id} - {name}】等{count}个资产位置为{status},'
                     ' {result}'),
        'value': ('批量编辑【{id} - {name}】等{count}个资产重要程度为{status},'
                  ' {result}'),
        'ip_mac_bond_single': '{status}了【{id} - {name}】IP/MAC绑定, {result}',
        'monitor_single': '{status}了【{id} - {name}】性能监控, {result}',
        'log_status_single': '{status}了【{id} - {name}】日志监控, {result}',
    }

    # 重要程度
    value_choices = {
        1: '低',
        2: '中',
        3: '高'
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.status_target = self.set_status_target()

    def set_status_target(self) -> str:
        single = len(self.request_body['ids'])
        if single == 1:
            if 'ip_mac_bond' in self.request_body:
                self.content_template = AssetsStatusGenerator.content_template[
                    'ip_mac_bond_single']
                return 'ip_mac_bond'
            elif 'monitor' in self.request_body:
                self.content_template = AssetsStatusGenerator.content_template[
                    'monitor_single']
                return 'monitor'
            else:
                self.content_template = AssetsStatusGenerator.content_template[
                    'log_status_single']
                return 'log_status'
        if 'ip_mac_bond' in self.request_body:
            target = 'ip_mac_bond'
        elif 'monitor' in self.request_body:
            target = 'monitor'
        elif 'responsible_user' in self.request_body:
            target = 'responsible_user'
        elif 'log_status' in self.request_body:
            target = 'log_status'
        elif 'value' in self.request_body:
            target = 'value'
        else:
            target = 'location'
        self.content_template = AssetsStatusGenerator.content_template[
            target]
        return target

    def get_status(self) -> str:
        """
        获取绑定状态或者修改状态
        :return: bool：启用或停用， str: 原样显示
        """
        status = self.request_body[self.status_target]
        if isinstance(status, bool):
            return '启用' if self.request_body[self.status_target] else '停用'
        elif isinstance(status, int):
            return self.value_choices[status]
        else:
            return status

    def get_content(self) -> str:
        """
        :return: 批量修改6-木链审计等25个资产IP/MAC绑定状态为启用
        """
        device_id = self.request_body['ids'][0]
        content = self.content_template.format(
            id=device_id,
            name=Device.objects.get(pk=device_id).name,
            count=len(self.request_body['ids']),
            status=self.get_status(),
            result=self.resp_result,
        )
        return content


@assets_config.register('device-batch', 'DELETE')
class AssetsBatchDeleteGenerator(AssetsLogMixin, LogGenerator, HookAbstract):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.item = kwargs.get('item')  # 删除资产的时候会用到它

    content_template = '批量删除【{id} - {name}】等{count}个资产, {result}'

    def get_content(self) -> str:
        dev_ids = self.request.GET.getlist('id')
        content = self.content_template.format(
            id=dev_ids[0], name=self.item.name, count=len(dev_ids),
            result=self.resp_result
        )
        return content

    @classmethod
    def get_previous(cls, request):
        resolved = resolve(request.path)
        ids = request.GET.getlist('id')
        try:
            item = resolved.func.cls.queryset.get(pk=ids[0])
        except AttributeError:
            item = None
        return {'item': item}


@assets_config.register('device-api', 'PUT')
class AllAssetsStatusGenerator(AssetsStatusGenerator):
    """
    批量修改给定筛选条件的所有资产
    """
    content_template = {
        'ip_mac_bond': ('批量编辑【{id} - {name}】等{count}个资产IP/MAC绑定为{status},'
                        ' {result}'),
        'monitor': ('批量编辑【{id} - {name}】等{count}个资产性能监控为{status},'
                    ' {result}'),
        'log_status': ('批量编辑【{id} - {name}】等{count}个资产日志监控为{status},'
                       ' {result}'),
        'responsible_user': ('批量编辑【{id} - {name}】等{count}个资产安全负责人为'
                             '{status}, {result}'),
        'location': ('批量编辑【{id} - {name}】等{count}个资产位置为{status},'
                     ' {result}'),
        'value': ('批量编辑【{id} - {name}】等{count}个资产重要程度为{status},'
                  ' {result}'),
    }

    def set_status_target(self) -> str:
        if 'ip_mac_bond' in self.request_body:
            target = 'ip_mac_bond'
        elif 'monitor' in self.request_body:
            target = 'monitor'
        elif 'responsible_user' in self.request_body:
            target = 'responsible_user'
        elif 'log_status' in self.request_body:
            target = 'log_status'
        elif 'value' in self.request_body:
            target = 'value'
        else:
            target = 'location'
        self.content_template = AllAssetsStatusGenerator.content_template[
            target]
        return target

    def get_content(self) -> str:
        data = self.response.data
        content = self.content_template.format(
            id=data['id'], name=data['device'], count=data['count'],
            status=self.get_status(), result=self.resp_result
        )
        return content


# @assets_config.register('dev_monitor_frequency', 'PATCH')
# class AssetsFrequencyGenerator(AssetsLogMixin, LogGenerator):
#     """
#     记录监控资产的设置
#     日志格式：
#     设置了监控频率：安全资产【】分钟，通信资产【】分钟
#     """
#     content_template = '设置了监控频率：{setting}, {result}'
#     setting_map = {
#         'communication_monitor_period': '通信资产',
#         'control_monitor_period': '工控资产',
#         'security_monitor_period': '安全资产',
#         'server_monitor_period': '主机资产',
#     }
#
#     def get_content(self) -> str:
#         """
#         :return: 设置了监控频率：安全资产3分钟，通信资产4分钟
#         """
#         content = self.content_template.format(
#             setting=self.get_setting_content(),
#             result=self.resp_result,
#         )
#         return content
#
#     def get_setting_content(self) -> str:
#         """
#         获取监控设置的内容
#         :return: 安全资产3分钟，通信资产4分钟
#         """
#         res = []
#         for key, value in self.request_body.items():
#             res.append(f'{self.setting_map[key]}{value}分钟')
#         return ', '.join(res)
#
#
# @assets_config.register('dev_monitor_threshold', 'PATCH')
# class AssetsThresholdGenerator(AssetsLogMixin, LogGenerator):
#     """
#     记录监控资产的设置
#     日志格式：
#     设置了使用率阈值：安全资产【】分钟，通信资产【】分钟
#     """
#     content_template = '设置了使用率阈值：{setting}, {result}'
#     setting_map = {
#         'security': {
#             'security_cpu_alert_percent': 'CPU告警阈值',
#             'security_disk_alert_percent': '内存告警阈值',
#             'security_memory_alert_percent': '硬盘告警阈值',
#             'name': '安全资产',
#         },
#         'communication': {
#             'communication_cpu_alert_percent': 'CPU告警阈值',
#             'communication_disk_alert_percent': '内存告警阈值',
#             'communication_memory_alert_percent': '硬盘告警阈值',
#             'name': '通信资产',
#         },
#         'server': {
#             'server_cpu_alert_percent': 'CPU告警阈值',
#             'server_disk_alert_percent': '内存告警阈值',
#             'server_memory_alert_percent': '硬盘告警阈值',
#             'name': '主机资产'
#         },
#         'control': {
#             'control_cpu_alert_percent': 'CPU告警阈值',
#             'control_memory_alert_percent': '内存告警阈值',
#             'name': '工控资产'
#         },
#     }
#
#     def get_content(self) -> str:
#         """
#         :return: 设置了监控频率：安全资产3分钟，通信资产4分钟
#         """
#         content = self.content_template.format(
#             setting=self.get_setting_content(),
#             result=self.resp_result,
#         )
#         return content
#
#     def get_setting_content(self) -> str:
#         """
#         获取监控设置的内容
#         :return: 安全资产3分钟，通信资产4分钟
#         """
#         res = []
#         for _, settings in self.setting_map.items():
#             settings = settings.copy()
#             name = settings.pop('name')
#             tmp = [name]
#             for key, value in settings.items():
#                 tmp.append(f'{value}{self.request_body[key]}%')
#             res.append(', '.join(tmp))
#         return '; '.join(res)


@assets_config.register('export-device', 'GET')
class DeviceExportLogGenerator(AssetsLogMixin, LogGenerator):
    """
    资产批量导出日志
    日志格式：
    批量导出了【资产ID】-【资产名称】等【X】个资产
    """
    content_template = '批量导出【{id} - {name}】等{count}个资产, {result}'

    def get_content(self):
        dev_ids = self.request.GET.getlist('dev_ids')
        device = Device.objects.get(id=dev_ids[0])

        content = self.content_template.format(
            id=device.id,
            name=device.name,
            count=len(dev_ids),
            result=self.resp_result,
        )
        return content


@assets_config.register('export-all-device', 'GET')
class AllDeviceExportLogGenerator(AssetsLogMixin, LogGenerator):
    """
    资产批量导出日志，根据筛选条件的批量导出
    """
    content_template = '批量导出【{id} - {name}】等{count}个资产, {result}'

    def get_content(self):
        serializer = DeviceFilterSerializer(data=self.request.GET)
        serializer.is_valid(raise_exception=True)
        devices = DeviceFilter(serializer.data, queryset=Device.objects.all()).qs
        device = devices.first()
        id = device.id if device else ''
        name = device.name if device else ''
        count = devices.count()
        content = self.content_template.format(
            id=id, name=name, count=count, result=self.resp_result
        )
        return content


@assets_config.register('device-batch', 'POST')
class DeviceImportLogGenerator(AssetsLogMixin, LogGenerator):
    """
    资产批量导入日志
    日子格式：
    批量导入了【资产ID】-【资产名称】等【X】个资产
    """
    content_template = '批量导入【{id} - {name}】等{count}个资产, {result}'

    def get_content(self):
        if self.result:
            device = Device.objects.get(name=self.response.data[0]['name'])
            content = self.content_template.format(
                id=device.id,
                name=device.name,
                count=len(self.response.data),
                result=self.resp_result
            )
        else:
            content = '批量导入, 失败'

        return content
