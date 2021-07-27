import datetime
import random
from traceback import print_exc

from Crypto.Cipher import AES
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from log.security_event import PasswordErrorEventLog
from setting.models import Setting
from user.models import UserExtension, GROUP_AUDITOR, \
    GROUP_CONFIG_ENGINEER, GROUP_SECURITY_ENGINEER, Group, ALL_GROUPS, \
    USERNAME_MAX_LENGTH, USERNAME_MIN_LENGTH
from user.models import username_validator, password_validator
from statistic.serializers import LockedUsernameSerializer, \
    AbnormalLoginSerializer
from utils.core.exceptions import CustomError
from utils.core.field_error import UserField
from utils.unified_redis import rs
from utils.helper import send_websocket_message

User = get_user_model()
CHARSET = [chr(i) for i in range(256)]


class PasswordCipher:
    def __init__(self, key):
        self.cipher = AES.new(key, AES.MODE_ECB)

    def encrypt(self, password):
        """
        加密密码组成为: 8位密码 + 8位盐 + 剩余密码 + 随机填充 + 2位密码长度(十进制字符串)
        加密后总位数是32
        :param password:
        :return:
        """
        password_length = len(password)

        if password_length < 8 or password_length > 16:
            raise ValueError('Invalid password.')
        salt = ''.join(random.sample(CHARSET, 8))
        padding_len = 22 - password_length
        padding = ''.join(random.sample(CHARSET, padding_len))
        with_salt = password[:8] + salt + password[8:]
        with_padding = with_salt + padding + '{:02d}'.format(password_length)
        return self.cipher.encrypt(with_padding.encode('latin')).hex()

    def decrypt(self, text):
        with_padding = self.cipher.decrypt(bytes.fromhex(text))
        if len(with_padding) != 32:
            raise ValueError('Invalid password!')
        password_length = int(with_padding[-2:])
        if password_length < 8 or password_length > 16:
            raise ValueError('Invalid password!')
        password = with_padding[:8] + with_padding[16:8 + password_length]
        salt = with_padding[8:16]
        return password.decode('latin'), salt


cipher = PasswordCipher('Bl666666666666lB')


class EncryptedPasswordField(serializers.CharField):
    """
    加密的密码字段.
    """

    def to_internal_value(self, data):
        if settings.TEST and settings.ALLOW_TEST_LOGIN:
            return super(EncryptedPasswordField, self).to_internal_value(data)
        try:
            password, salt = cipher.decrypt(data)
        except (TypeError, ValueError):
            raise CustomError(error_code=CustomError.PASSWORD_FORMAT_ERROR)
        return super(EncryptedPasswordField, self).to_internal_value(password)

    def to_representation(self, value):
        if settings.TEST and settings.ALLOW_TEST_LOGIN:
            return super(EncryptedPasswordField, self).to_representation(value)
        representation = super(EncryptedPasswordField, self).to_representation(
            value)
        return cipher.encrypt(representation)


def change_to_day(format_time):
    # change datetime to days
    t = timezone.now() - format_time
    r = t.days
    return r


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(label='用户名',
                                     validators=[username_validator])
    password = serializers.CharField(label='密码')
    ip = serializers.IPAddressField(label='请求登录的IP')

    def to_internal_value(self, data):
        try:
            return super().to_internal_value(data)
        except ValidationError:
            raise CustomError(error_code=CustomError.USERNAME_FORMAT_ERROR)

    def validate(self, data):
        current = timezone.now()
        username = data['username']
        if not settings.DEBUG and settings.TEST:
            password, salt = data['password'], ''.join(
                random.sample(CHARSET, 8))
        else:
            try:
                password, salt = cipher.decrypt(data['password'])
            except (TypeError, ValueError):
                raise CustomError(error_code=CustomError.PASSWORD_FORMAT_ERROR)

        # 获取用户登录失败处理参数
        setting, created = Setting.objects.get_or_create(id=1)
        lockout_threshold = setting.lockout_threshold  # 最大登录失败次数
        lockout_duration = setting.lockout_duration  # 锁定时间，分钟
        reset_lockout_counter_after = setting.reset_lockout_counter_after  # 重新计数时间，分钟
        user_exists = User.objects.filter(username=username).exists()
        user_ext, created = UserExtension.objects.get_or_create(name=username)
        user_ext.last_login = current
        user_ext.ip = data['ip']
        user_ext.save()
        self.abnormal_login_websocket(current)  # 推送异常登录信息
        user = None
        try:
            user = User.objects.get(username=username)
            if not user.is_active:
                raise CustomError({'error': CustomError.ACCOUNT_BANNED})
            # 用户在封禁期内直接返回用户被封异常，否则解封用户
            if user_ext.banned:
                timedelta = current - user_ext.last_failure
                remaining_time = lockout_duration - (
                        timedelta.days * 24 * 60 + timedelta.seconds // 60)
                if remaining_time > 0:
                    raise CustomError(
                        error_code=CustomError.LOGIN_FAIL_TIME_EXCEED_ERROR,
                        message=CustomError.MESSAGE_MAP[
                            CustomError.LOGIN_FAIL_TIME_EXCEED_ERROR].format(
                            remaining_time))
                else:
                    user_ext.banned = False
                    user_ext.count = 0
                    user_ext.save()
            # 检查用户名与密码是否匹配
            # only users belong to specified groups are allowed to login.
            if user.group.name in ALL_GROUPS and user.check_password(password):
                if rs.exists('_p_' + username):
                    if rs.sadd('_p_' + username, salt):
                        return {'user': user}
                else:
                    if rs.sadd('_p_' + username, salt):
                        rs.expire('_p_' + username, 7776000)  # 90天后清空盐池
                        return {'user': user}
        except (
                User.DoesNotExist, Group.DoesNotExist,
                Group.MultipleObjectsReturned):
            print_exc()
            pass

        # 如果用户上次登录失败在重置计数时间内，则增加登录失败次数
        if user_ext.last_failure and current - user_ext.last_failure < datetime.timedelta(
                minutes=reset_lockout_counter_after):
            user_ext.count += 1
        # 否则重新计数
        else:
            user_ext.count = 1
        user_ext.last_failure = current
        user_ext.save()
        # 若失败次数大于设定值，则禁用用户
        if user_ext.count >= lockout_threshold:
            user_ext.banned = True
            user_ext.save()
            content = CustomError.MESSAGE_MAP[
                CustomError.LOGIN_FAIL_TIME_EXCEED_ERROR].format(
                lockout_duration)
            self.locked_user_websocket()
            event = PasswordErrorEventLog(threshold=lockout_threshold,
                                          lockout_duration=lockout_duration)
            event.generate()
            raise CustomError(
                error_code=CustomError.LOGIN_FAIL_TIME_EXCEED_ERROR,
                message=content)
        raise CustomError({'error': CustomError.USER_NAME_OR_PWS_ERROR})

    def locked_user_websocket(self):
        """
        当有用户登录失败时，推送锁定账户的websocket
        """
        queryset = UserExtension.objects.filter(banned=True).order_by(
            '-last_failure')
        serializer = LockedUsernameSerializer(queryset[:5], many=True)
        message = {
            'message': 'abnormal',
            'data': {'locked_user': serializer.data},
        }
        send_websocket_message('abnormal', message)

    def abnormal_login_websocket(self, login_time: datetime):
        """
        异常时间尝试登录的用户，推送异常登录的websocket
        """
        if not (14 <= login_time.hour <= 22):
            return
        serializer = AbnormalLoginSerializer(UserExtension.abnormal_login()[:5],
                                             many=True)
        message = {
            'message': 'abnormal',
            'data': {'abnormal_login': serializer.data}
        }
        send_websocket_message('abnormal', message)


class PasswordSerializer(serializers.Serializer):
    password = EncryptedPasswordField(validators=[password_validator])


class ModifyPasswordSerializer(serializers.Serializer):
    password = EncryptedPasswordField(validators=[password_validator])
    new_password1 = EncryptedPasswordField(validators=[password_validator])
    new_password2 = EncryptedPasswordField(validators=[password_validator])

    def to_internal_value(self, data):
        try:
            return super().to_internal_value(data)
        except ValidationError:
            raise CustomError(error_code=CustomError.PASSWORD_FORMAT_ERROR)

    def validate(self, data):
        if data.get('new_password1') != data.get('new_password2'):
            raise CustomError(error_code=CustomError.PASSWORD_NOT_CONSISTENT)

        return data


class UserSerializer(serializers.ModelSerializer):
    group = serializers.CharField(help_text='用户组', source='group.name')

    class Meta:
        model = User
        fields = ('id', 'username', 'date_joined', 'is_active', 'group',
                  'last_modify')

    def to_representation(self, instance):
        ret = super(UserSerializer, self).to_representation(instance)
        user_ext, created = UserExtension.objects.get_or_create(
            name=instance.username)
        ret['description'] = user_ext.description
        last_change_psd = user_ext.last_change_psd
        last_change_psd_to_day = 0
        if last_change_psd:
            last_change_psd_to_day = change_to_day(last_change_psd)
        ret['last_change_psd'] = last_change_psd_to_day
        return ret


class UserCreateSerializer(serializers.Serializer):
    username = serializers.CharField(
        validators=[username_validator], min_length=USERNAME_MIN_LENGTH,
        max_length=USERNAME_MAX_LENGTH
    )
    password1 = EncryptedPasswordField(validators=[password_validator])
    password2 = EncryptedPasswordField(validators=[password_validator])
    group = serializers.SlugRelatedField(
        queryset=Group.objects.filter(
            name__in=[GROUP_AUDITOR, GROUP_CONFIG_ENGINEER,
                      GROUP_SECURITY_ENGINEER]),
        slug_field='name')
    description = serializers.CharField(
        max_length=100, required=False, allow_null=True, allow_blank=True,
        error_messages={'max_length': UserField.DESCRIPTION_LENGTH_EXCEED}
    )
    is_active = serializers.BooleanField(label='启用状态')

    def to_internal_value(self, data):
        try:
            return super().to_internal_value(data)
        except ValidationError as e:
            codes = e.get_codes()
            if 'password1' in codes or 'password2' in codes:
                raise CustomError(error_code=CustomError.PASSWORD_FORMAT_ERROR)
            if 'username' in codes:
                raise CustomError(error_code=CustomError.USERNAME_FORMAT_ERROR)
            raise e

    def validate(self, data):
        if data.get('password1') != data.get('password2'):
            raise CustomError(
                error_code=CustomError.PASSWORD_NOT_CONSISTENT)
        # settings.LOCAL_NAME and 'anonymous' are internal used.
        if User.objects.filter(
                username=data.get('username')).exists() or data.get(
            'username') == 'anonymous' or \
                data.get('username') == getattr(settings, 'LOCAL_NAME',
                                                'local'):
            raise CustomError(
                {'error': CustomError.USERNAME_ALREADY_EXISTS_ERROR})
        return data

    def to_representation(self, user):
        data = {
            'id': user.id,
            'username': user.username,
            'is_active': user.is_active,
            'group': self.initial_data.get('group'),
            'description': self.initial_data.get('description')
        }
        return data

    def create(self, validated_data):
        username = validated_data['username']
        password = validated_data['password1']
        group = validated_data['group']
        is_active = validated_data['is_active']
        description = validated_data.get('description')
        user = User.objects.create_user(username, password=password,
                                        group=group, is_active=is_active)
        # if someone has tried to login before the user is created, then user extension is already existed.
        user_ext, created = UserExtension.objects.get_or_create(name=username)
        user_ext.description = description
        user_ext.save()
        return user


class UserUpdateSerializer(serializers.Serializer):
    is_active = serializers.BooleanField(required=False)
    group = serializers.SlugRelatedField(
        required=False,
        queryset=Group.objects.filter(name__in=[
            GROUP_AUDITOR, GROUP_CONFIG_ENGINEER, GROUP_SECURITY_ENGINEER]),
        slug_field='name')
    description = serializers.CharField(max_length=200, required=False,
                                        allow_null=True, allow_blank=True)

    def to_representation(self, user):
        data = {
            'id': user.id,
            'username': user.username,
            'is_active': user.is_active,
        }
        return data

    def update(self, user, validated_data):
        group = validated_data.get('group')
        is_active = validated_data.get('is_active')
        user_ext, created = UserExtension.objects.get_or_create(
            name=user.username)
        if group:
            user.group = group
        if is_active is not None:
            user.is_active = is_active
            if is_active:
                user_ext.banned = False
                user_ext.count = 0
                user_ext.save()
        if 'description' in validated_data:
            user_ext, created = UserExtension.objects.get_or_create(
                name=user.username)
            user_ext.description = validated_data['description']
            user_ext.save()
        user.save()
        return user
