from django.contrib.auth.models import AnonymousUser, User

from base_app.models import Device
from base_app.serializers import BatchOperationSerializer
from log.models import UnifiedForumLog, DeviceAllAlert
from setting.models import Setting
from user.models import UserExtension
from utils.helper import format_log_time


def get_pwd_alert_data(user, pwd_modified_duration):

    username = user.username

    try:
        group = user.group.values()[0]['name']
        group_name_dict = dict(
            Admin='管理员',
            Engineer='工程师',
            Auditor='审计员',
            Config_Engineer='配置工程师',
        )
        group_name = group_name_dict.get(group)
        sec_desc_temp = '{} ({}) 密码{}天未修改'.format(username, group_name, pwd_modified_duration)
    except:
        sec_desc_temp = '{} 密码{}天未修改'.format(username, pwd_modified_duration)

    data = dict(
        category=DeviceAllAlert.EVENT_SYS,
        type=DeviceAllAlert.ACCOUNT_MANAGE,
        sec_desc=sec_desc_temp,
        level=DeviceAllAlert.LEVEL_LOW,
    )

    return data


GROUP_NAME_MAP = {
    'Admin': '超级管理员',
    'Engineer': '工程师',
    'Auditor': '审计员',
    'Config_Engineer': '配置工程师',
}


class LogGenerator(object):
    content_template = None
    data_template = None
    log_cls = UnifiedForumLog
    log_category = ''

    def __init__(self, request, request_body, result, response, *args, **kwargs):
        self.request = request
        self.response = response
        self.user = request.user
        self.ip = request.META['REMOTE_ADDR']
        self.request_body = request_body
        self.result = result
        self._check_template()

    def get_content(self):
        return self.content_template.format(user=print_user(self.user),
                                            time=format_log_time(),
                                            result=print_result(self.result))

    def get_group(self):
        if self.user.is_anonymous:
            return ''
        return self.user.groups.get().name

    def get_data(self):
        self.data_template['result'] = self.result
        self.data_template['user'] = self.user
        self.data_template['group'] = self.get_group()
        self.data_template['content'] = self.get_content()
        self.data_template['category'] = self.log_category
        self.data_template['ip'] = self.ip
        return self.data_template

    def generate_log(self):
        """
        将格式化后的数据存入数据库
        """
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


class ManageDeviceDetailLogGenerator(LogGenerator):

    content_template = '{}{}资产删除成功'
    data_template = {'type': DeviceAllAlert.LOGIN_LOGOUT}
    log_category = UnifiedForumLog.CATEGORY_OPERATION

    def generate_log(self):
        # 利用产出 log 的函数，去产生告警
        user = self.request.user
        method = self.request.method
        ip = self.request.META.get('REMOTE_ADDR')

        if method == 'DELETE':
            self.generate_delete_device_alert(user)
            self.generate_delete_log(user, ip)

        if method == 'PUT' or method == 'PATCH':
            self.generate_update_device_alert(user)
            self.generate_update_log(user, ip)

    def _get_update_device_alert(self, user):

        if user is AnonymousUser:
            sec_desc_temp = '{}资产更新成功'.format(' ')

        else:
            username = user.username
            try:
                group = user.group.values()[0]['name']
                group_name_dict = dict(
                    Admin='管理员',
                    Engineer='工程师',
                    Auditor='审计员',
                    Config_Engineer='配置工程师',
                )
                group_name = group_name_dict.get(group)
                sec_desc_temp = '{}进行（{}）资产更新成功'.format(username, group_name)
            except:
                sec_desc_temp = '{} 进行资产更新成功'.format(username)

        data = dict(
            category=DeviceAllAlert.EVENT_ASSET,
            type=DeviceAllAlert.ALL_ASSETS,
            sec_desc=sec_desc_temp,
            level=DeviceAllAlert.LEVEL_LOW,
        )
        return data

    def _get_delete_device_alert(self, user):

        if user is AnonymousUser:
            sec_desc_temp = '{}资产删除成功'.format('匿名用户')

        else:
            username = user.username
            try:
                group = user.group.values()[0]['name']
                group_name_dict = dict(
                    Admin='管理员',
                    Engineer='工程师',
                    Auditor='审计员',
                    Config_Engineer='配置工程师',
                )
                group_name = group_name_dict.get(group)
                sec_desc_temp = '{}（{}）资产删除成功'.format(username, group_name)
            except:
                sec_desc_temp = '{} 资产删除成功'.format(username)

        data = dict(
            category=DeviceAllAlert.EVENT_ASSET,
            type=DeviceAllAlert.ALL_ASSETS,
            sec_desc=sec_desc_temp,
            level=DeviceAllAlert.LEVEL_LOW,
        )

        return data

    def _get_delete_device_log(self, user, ip='127.0.0.1'):

        if user is AnonymousUser:
            content = '{}资产删除成功'.format('匿名用户')

        else:
            username = user.username
            try:
                group = user.group.values()[0]['name']
                group_name_dict = dict(
                    Admin='管理员',
                    Engineer='工程师',
                    Auditor='审计员',
                    Config_Engineer='配置工程师',
                )
                group_name = group_name_dict.get(group)
                content = '{}（{}）资产删除成功'.format(username, group_name)
            except:
                content = '{} 资产删除成功'.format(username)

        data = {
            'type': UnifiedForumLog.TYPE_ASSETS,
            'content': content,
            'result': True,
            'category': UnifiedForumLog.CATEGORY_OPERATION,
            'ip': self.ip,
            'user':user,
        }
        return data

    def _get_update_device_log(self, user, ip='127.0.0.1'):

        if user is AnonymousUser:
            content = '{}资产更新成功'.format('匿名用户')

        else:
            username = user.username
            try:
                group = user.group.values()[0]['name']
                group_name_dict = dict(
                    Admin='管理员',
                    Engineer='工程师',
                    Auditor='审计员',
                    Config_Engineer='配置工程师',
                )
                group_name = group_name_dict.get(group)
                content = '{}（{}）资产更新成功'.format(username, group_name)
            except:
                content = '{} 资产更新成功'.format(username)

        data = {
            'type': UnifiedForumLog.TYPE_ASSETS,
            'content': content,
            'result': True,
            'category': UnifiedForumLog.CATEGORY_OPERATION,
            'ip': self.ip,
            'user': user,
        }

        return data

    def generate_update_device_alert(self, user):
        data = self._get_update_device_alert(user)
        DeviceAllAlert.objects.create(**data)

    def generate_update_log(self, user, ip):
        data = self._get_update_device_log(user)
        UnifiedForumLog.objects.create(**data)


    def generate_delete_device_alert(self, user):
        data = self._get_delete_device_alert(user)
        DeviceAllAlert.objects.create(**data)

    def generate_delete_log(self, user, ip):
        data = self._get_delete_device_log(user, ip)
        UnifiedForumLog.objects.create(**data)


class ManageDeviceListLogGenerator(LogGenerator):
    content_template = '{}{}操作成功'
    log_category = UnifiedForumLog.CATEGORY_OPERATION

    data_template = {
        'type': UnifiedForumLog.TYPE_ASSETS,
        'category': UnifiedForumLog.CATEGORY_OPERATION,
    }

    def get_content(self):
        user = self.request.user

        if user is AnonymousUser:
            content = '{}资产新增成功'.format('匿名用户')

        else:
            username = user.username
            try:
                group = user.group.values()[0]['name']
                group_name_dict = dict(
                    Admin='管理员',
                    Engineer='工程师',
                    Auditor='审计员',
                    Config_Engineer='配置工程师',
                )
                group_name = group_name_dict.get(group)
                content = '{}（{}）资产新增成功'.format(username, group_name)
            except:
                content = '{}进行资产新增成功'.format(username)
        return content


class AuthLogGenerator(LogGenerator):
    log_category = UnifiedForumLog.CATEGORY_USER_MANAGEMENT


class ManagementLogGenerator(LogGenerator):
    log_category = UnifiedForumLog.CATEGORY_OPERATION


class LoginGenerator(LogGenerator):
    log_category = UnifiedForumLog.CATEGORY_LOGIN_LOGOUT
    content_template = '{user}于{time}登录管理平台，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_LOGIN}

    def _get_login_alert_desc(self, user, setting):
        username = user.username
        chances = setting.lockout_threshold
        lock_duration = setting.lockout_duration

        try:
            group = user.group.values()[0]['name']
            group_name_dict = dict(
                Admin='管理员',
                Engineer='工程师',
                Auditor='审计员',
                Config_Engineer='配置工程师',
            )
            group_name = group_name_dict.get(group)

            sec_desc_temp = '{}（{}）登录失败{}次达到上限，账号锁定{}分钟'.\
                            format(username, group_name, chances, lock_duration)
        except:
            sec_desc_temp = '{}登录失败{}次达到上限，账号锁定{}分钟'. \
                format(username, chances, lock_duration)

        data = dict(
            category=DeviceAllAlert.EVENT_SYS,
            type=DeviceAllAlert.LOGIN_LOGOUT,
            sec_desc=sec_desc_temp,
            level=DeviceAllAlert.LEVEL_MEDIUM,
        )
        return data

    def generate_device_alert(self, username):

        user = User.objects.get(username=username)
        user_ext = UserExtension.objects.get(name=username)

        if user:
            current_ip = self.request.META.get("REMOTE_ADDR")
            setting, setting_existe = Setting.objects.get_or_create(id=1)
            ip_illegal = setting.ip_limit_enable and (current_ip in setting.allow_ip)

            if (user_ext and user_ext.banned is True) or ip_illegal:
                data = self._get_login_alert_desc(user, setting)
                DeviceAllAlert.objects.create(**data)
        else:
            current_ip = self.request.META.get("REMOTE_ADDR")
            sec_desc_temp = '{}尝试登录'.format(current_ip)
            data = dict(
                category=DeviceAllAlert.EVENT_SYS,
                type=DeviceAllAlert.ACCOUNT_MANAGE,
                sec_desc=sec_desc_temp,
                level=DeviceAllAlert.LEVEL_LOW,
            )
            DeviceAllAlert.objects.create(**data)

    def get_content(self):
        if self.result:
            return super(LoginGenerator, self).get_content()
        else:
            username = self.request_body['username']
            user_ext = UserExtension.objects.get(name=username)
            user_exists = User.objects.filter(username=username).exists()

            if user_exists and user_ext.count >= 5:
                setting, setting_exist = Setting.objects.get_or_create(id=1)
                lock_duration = setting.lockout_duration
                fail_content_template = '{} 登录失败达到上限，账号锁定{}分钟'. \
                    format(username, lock_duration)
                # 第五次登录失败的时候才会产生一次告警
                self.generate_device_alert(username=username)
                return fail_content_template

            return self.content_template.format(user=username,
                                                time=format_log_time(),
                                                result=print_result(self.result))

    def get_data(self):
        data_template = super(LoginGenerator, self).get_data()
        if not self.result:
            data_template['user'] = self.request_body['username']
        return data_template


class ChangePSWAuthLogGenerator(AuthLogGenerator):
    content_template = '{user}于{time}修改密码，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_AUTH}


class ResetPSWAuthLogGenerator(AuthLogGenerator):
    content_template = '{super_user}于{time}修改{user}密码，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_AUTH}

    def get_content(self):
        kwargs = self.request.resolver_match.kwargs
        user_id = kwargs['pk']
        user = User.objects.get(id=user_id)
        return self.content_template.format(super_user=print_user(self.user),
                                            user=print_user(user),
                                            time=format_log_time(),
                                            result=print_result(self.result))

class AddUserAuthLogGenerator(AuthLogGenerator):
    content_template = '{super_user}于{time}新增{user}，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_AUTH}

    def generate_device_alert(self, username, groups):
        username = self.request_body['username']
        group_name = GROUP_NAME_MAP[groups]
        sec_desc_temp = '管理员创建账户{} {}'.format(username, group_name, )

        data = dict(
            category=DeviceAllAlert.EVENT_SYS,
            type=DeviceAllAlert.ACCOUNT_MANAGE,
            sec_desc=sec_desc_temp,
            level=DeviceAllAlert.LEVEL_LOW,
        )

        DeviceAllAlert.objects.create(**data)


    def get_content(self):
        groups = self.request_body['groups']
        username = self.request_body['username']
        self.generate_device_alert(username, groups)
        return self.content_template.format(super_user=print_user(self.user),
                                            user='{} {}'.format(GROUP_NAME_MAP[groups], username),
                                            time=format_log_time(),
                                            result=print_result(self.result))


class UpdateUserAuthLogGenerator(AuthLogGenerator):
    content_template = '{super_user}于{time}修改{user}{changes}，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_AUTH}

    def get_content(self):
        kwargs = self.request.resolver_match.kwargs
        user_id = kwargs['pk']
        user = User.objects.get(id=user_id)
        changes = ''
        # serializer = UserUpdateSerializer(data=self.request_body)
        groups = self.request_body.get('groups', None)
        is_active = self.request_body.get('is_active', None)
        description = self.request_body.get('description', None)
        changes += '，用户组：{}'.format(GROUP_NAME_MAP[groups]) if groups else ''
        changes += '，用户状态：{}'.format('启用' if is_active else '禁用')
        changes += '，备注：{}'.format(description) if description else ''
        return self.content_template.format(super_user=print_user(self.user),
                                            user=print_user(user),
                                            time=format_log_time(),
                                            result=print_result(self.result),
                                            changes=changes)


class AddDevManagementLogGenerator(ManagementLogGenerator):
    content_template = '{user}于{time}新增设备{dev_name}，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_ASSETS}

    def get_content(self):
        dev_name = self.request_body['name']
        return self.content_template.format(user=print_user(self.user),
                                            time=format_log_time(),
                                            dev_name=dev_name,
                                            result=print_result(self.result))


class UpdateDevManagementLogGenerator(ManagementLogGenerator):
    content_template = '{user}于{time}编辑设备{dev_name}，{changes}，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_ASSETS}

    def get_content(self):
        kwargs = self.request.resolver_match.kwargs
        dev_id = kwargs['pk']
        device = Device.objects.get(id=dev_id)
        changes = ''
        name = self.request_body.get('name', None)
        location = self.request_body.get('location', None)
        responsible_user = self.request_body.get('responsible_user', None)
        changes += '，设备名：{}'.format(name) if name else ''
        changes += '，位置：{}'.format(location) if location else ''
        changes += '，负责人：{}'.format(responsible_user) if responsible_user else ''
        return self.content_template.format(user=print_user(self.user),
                                            time=format_log_time(),
                                            dev_name=device.name,
                                            changes=changes,
                                            result=print_result(self.result)
                                            )


class DevBatchOperationManagementLogGenerator(ManagementLogGenerator):

    content_template = '{user}于{time}{operation}{dev_names}，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_ASSETS}

    def get_content(self):
        # print(self.request_body)
        dev_ids = self.request_body['dev_ids']
        operation = self.request_body['operation']
        devs = Device.objects.filter(id__in=dev_ids)
        dev_names = [dev.name for dev in devs]
        return self.content_template.format(user=print_user(self.user),
                                            time=format_log_time(),
                                            operation=print_batch_operation(operation),
                                            dev_names='，'.join(dev_names),
                                            result=print_result(self.result)
                                            )


class SetIpManagementLogGenerator(ManagementLogGenerator):

    content_template = '{user}于{time}修改平台ip，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_SYSTEM}


class SetTimeManagementLogGenerator(ManagementLogGenerator):

    content_template = '{user}于{time}修改平台时间，{result}'
    data_template = {'type': UnifiedForumLog.TYPE_SYSTEM}


class AddTemplateManagementLogGenerator(ManagementLogGenerator):

    content_template = '{user}于{time}新建模板{template},{result}。'
    data_template = {'type': UnifiedForumLog.TYPE_STRATEGY}

    def get_content(self):
        template = self.request_body['name']
        return self.content_template.format(user=print_user(self.user),
                                            time=format_log_time(),
                                            template=template,
                                            result=print_result(self.result))


class ApplyStrategyManagementLogGenerator(ManagementLogGenerator):

    content_template = '{user}于{time} 对{device}启用策略，{result}。'
    data_template = {'type': UnifiedForumLog.TYPE_STRATEGY}

    def get_content(self):
        kwargs = self.request.resolver_match.kwargs
        dev_id = kwargs['pk']
        device = Device.objects.get(id=dev_id)
        return self.content_template.format(user=print_user(self.user),
                                            time=format_log_time(),
                                            device=device.name,
                                            result=print_result(self.result))


def print_result(result):
    return '成功' if result else '失败'


def print_user(user):
    if isinstance(user, AnonymousUser):
        return 'anonymous'
    else:
        return '{}{}'.format(GROUP_NAME_MAP[user.groups.all()[0].name], user.username)


def print_batch_operation(operation):
    if operation == BatchOperationSerializer.REBOOT:
        return '重启'
    elif operation == BatchOperationSerializer.UN_REGISTER:
        return '解绑'
