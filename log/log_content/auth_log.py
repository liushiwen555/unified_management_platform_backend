"""
授权管理的日志
"""
from django.urls import resolve
from django.contrib.auth import get_user_model

from log.log_content.log_generator import LogGenerator, LogConfig, HookAbstract
from log.models import UnifiedForumLog
from log.security_event import UserEventLog
from utils.constants import GROUP_NAME_DICT

auth_config = LogConfig()
User = get_user_model()


class AuthLogMixin:
    data_template = {
        'type': UnifiedForumLog.TYPE_AUTH,
    }
    log_category = UnifiedForumLog.CATEGORY_USER_MANAGEMENT


@auth_config.register('user-view-detail', ['PATCH', 'DELETE', 'POST'],
                      additional_info=True)
@auth_config.register('user-view-list', 'POST')
class UpdateUserAuthLogGenerator(AuthLogMixin, LogGenerator, HookAbstract):
    """
    更新用户权限日志
    日志格式:
    修改 【旧角色】【用户】为【新角色】, 【启用/停用】【用户】账号
    """
    content_template = {
        'PATCH': '编辑【{previous}{user}】为【{current}】, {result}',
        'DELETE': '删除【{previous}{user}】账号, {result}',
        'POST': '添加【{previous}{user}】账号, {result}',
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.group = kwargs.get('group')
        self.item = kwargs.get('item')
        self.content_template = UpdateUserAuthLogGenerator.content_template[
            self.method]

    def get_content(self):
        return self._get_content()

    def _get_content(self):
        if self.method == 'PATCH':
            content = self.content_template.format(
                previous=GROUP_NAME_DICT[self.group],
                user=self.item.username,
                current=GROUP_NAME_DICT[self.request_body['group']],
                result=self.resp_result,
            )
        elif self.method == 'DELETE':
            content = self.content_template.format(
                previous=GROUP_NAME_DICT[self.group],
                user=self.item.username,
                result=self.resp_result,
            )
        else:
            content = self.content_template.format(
                previous=GROUP_NAME_DICT[self.request_body['group']],
                user=self.response.data['username'],
                result=self.resp_result,
            )
        return content

    def _get_data(self):
        self.data_template = self.get_data()
        self.data_template['content'] = \
            '{active}【{previous}{user}】账号, {result}'.format(
                active=self.get_status(),
                previous=GROUP_NAME_DICT[self.request_body['group']],
                user=self.item.username,
                result=self.resp_result,
        )
        return self.data_template

    def generate_log(self):
        super().generate_log()
        if self.method == 'PATCH':
            # 更新用户的时候，需要记录两条日志，一个是权限的修改，另一个是状态的修改
            self.log_cls.objects.create(**self._get_data())
        elif self.method == 'POST':
            event = UserEventLog(content=self.content)
            event.generate()

    def get_status(self):
        return '启用' if self.request_body.get('is_active') else '停用'

    @classmethod
    def get_previous(cls, request):
        resolved = resolve(request.path)
        pk = resolved.kwargs.get('pk')
        item = resolved.func.cls.queryset.get(pk=pk)
        return {'item': item, 'username': request.user.username,
                'group': item.group.name}


@auth_config.register('reset-password', 'POST')
class ResetPasswordGenerator(AuthLogMixin, LogGenerator):
    content_template = '重置【{group}{user}】密码, {result}'

    def get_content(self):
        user = self.get_user()
        return self.content_template.format(
            group=GROUP_NAME_DICT.get(user.group.name, ''),
            user=user.username,
            result=self.resp_result,
        )

    def get_user(self):
        resolved = resolve(self.request.path)
        pk = resolved.kwargs.get('pk')

        try:
            user = User.objects.get(id=pk)
        except User.DoesNotExist:
            user = User(username='AnonymousUser', group='')
        return user
