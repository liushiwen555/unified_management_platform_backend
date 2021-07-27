from typing import Dict, List

from rest_framework.exceptions import APIException, ValidationError
from rest_framework.views import exception_handler
from utils.core.field_error import *


class ErrorCode:
    """
    used for custom error code. content is {"error": code}, code is defined as follows:
    // 后端接口-提示
    - 1001  用户名或密码错误
    - 1002  用户登录失败次数过多，请在x分钟后重新尝试
    - 1003  用户IP不允许登录
    - 1004  用户长时间无操作自动退出
    - 1005  您输入的用户名已被占用，请重新输入
    - 1006  管理员密码错误
    - 1007  原密码错误
    - 1008  IP地址重复，请重新输入
    - 1009  MAC地址重复，请重新输
    - 1010  设备ruleid重复
    - 1011  策略下发失败
    - 1012  设备重复注册
    - 1013  用户被禁用
    - 1019  用户名只能包含大小写字母数字及下划线，必须以字母开头，最长32位

    - 2000  批量操作时，部分下位机错误
    - 2001  未开启统一管理时，尝试修改数据或访问统一管理接口（除注册接口）
    - 2002  统一管理平台访问时，与注册的管理平台IP不一致
    - 2003  统一管理平台访问时，secret不正确
    - 2004  统一管理平台访问时，访问了非管理接口
    - 2005  在下发策略时编辑了该设备的策略


    - 3000  防火墙API调用失败
    - 3001  防火墙自定义白名单启用/停用/删除失败
    - 3002  防火墙自定义白名单正在学习，不能进行相关操作
    - 3003  防火墙自定义白名单启用状态下不能删除

    - 4000  禁止删除系统内置模板
    - 4001  禁止修改系统内置模板
    - 4002  模板名称、资产类别、资产类型禁止重复
    """

    FIELD_ERROR = 1000
    USER_NAME_OR_PWS_ERROR = 1001
    LOGIN_FAIL_TIME_EXCEED_ERROR = 1002
    IP_LIMIT_ERROR = 1003
    AUTO_LOGOUT_ERROR = 1004
    USERNAME_ALREADY_EXISTS_ERROR = 1005
    ADMIN_PSW_ERROR = 1006
    ORIGINAL_PSW_ERROR = 1007
    IP_REPEAT_ERROR = 1008
    MAC_REPEAT_ERROR = 1009
    DEVICE_AND_RULE_ID_EXIST_ERROR = 1010
    APPLY_STRATEGY_FAIL = 1011
    DEVICE_ALREADY_REGISTERED = 1012
    ACCOUNT_BANNED = 1013
    SYNC_STRATEGY_FAIL = 1014
    BULK_IMPORT_DEVICE_TEMP_ERROR = 1015
    EXPORT_REPORT_ERROR = 1016
    DEVICE_ALLERT_ERROR = 1017
    APPLY_STRATEGY_FAIL_DEVICE_OFFLINE = 1018
    USERNAME_FORMAT_ERROR = 1019
    PASSWORD_FORMAT_ERROR = 1020
    PASSWORD_NOT_CONSISTENT = 1021
    ASSET_NOT_FOUND = 1022

    # 平台和下位机设备交互时的错误
    BATCH_OPERATION_PART_FAIL = 2000
    DEVICE_NOT_REGISTERED = 2001
    IP_NOT_MATCH = 2002
    BAD_SECRET = 2003
    NONE_MANAGEMENT_API = 2004
    EDIT_STRATEGY_WHILE_APPLYING = 2005

    # 防火墙部分api的错误
    FIREWALL_API_FAIL = 3000
    LEARNED_WHITELIST_ACTIVATION_FAIL = 3001
    LEARNED_WHITELIST_OPERATION_WHILE_LEARNING = 3002
    LEARNED_WHITELIST_DELETING_ACTIVE_ITEM = 3003
    # 审计API
    AUDITOR_PROTOCOL_FAIL = 3010
    NO_AUDITOR_FOUND = 3011

    # 模板库错误
    UN_ALLOWED_TO_DELETE_SYSTEM_TEMPLATE = 4000
    UN_ALLOWED_TO_EDIT_SYSTEM_TEMPLATE = 4001
    REPEATED_NAME_CATEGORY_TYPE_ERROR = 4002

    # 设置错误
    IP_TABLES_NULL_ERROR = 5001
    NTP_SETTING_ERROR = 5002
    CITY_NOT_FOUND = 5003

    status_code = 499
    default_detail = 'Custom error.'
    default_code = 'custom_error'

    MESSAGE_MAP = {
        USER_NAME_OR_PWS_ERROR: '用户名或密码错误',
        LOGIN_FAIL_TIME_EXCEED_ERROR: '用户登录失败次数过多，请在{}分钟后重新尝试',
        IP_LIMIT_ERROR: '用户IP不允许登录',
        AUTO_LOGOUT_ERROR: '用户长时间无操作自动退出',
        USERNAME_ALREADY_EXISTS_ERROR: UserField.USERNAME_DUPLICATE,
        ADMIN_PSW_ERROR: '管理员密码错误',
        ORIGINAL_PSW_ERROR: '原密码错误',
        IP_REPEAT_ERROR: AssetsField.IP_DUPLICATE,
        MAC_REPEAT_ERROR: AssetsField.MAC_DUPLICATE,
        DEVICE_AND_RULE_ID_EXIST_ERROR: '设备ruleid重复',
        APPLY_STRATEGY_FAIL: '策略下发失败',
        DEVICE_ALREADY_REGISTERED: '设备重复注册',
        ACCOUNT_BANNED: '用户被禁用，请联系管理员解决',
        SYNC_STRATEGY_FAIL: '同步策略失败',
        BULK_IMPORT_DEVICE_TEMP_ERROR: '批量导入资产失败',
        EXPORT_REPORT_ERROR: '导出报表失败',
        DEVICE_ALLERT_ERROR: '告警处理失败',
        APPLY_STRATEGY_FAIL_DEVICE_OFFLINE: '设备离线，应用策略失败',
        USERNAME_FORMAT_ERROR: '用户名只能包含大小写字母数字，必须以字母开头，最长16位，最短6位',
        PASSWORD_FORMAT_ERROR: '密码由大小写英文字母/数字/符号至少3种组成，8-16位字符',
        PASSWORD_NOT_CONSISTENT: '两次密码不一致',
        ASSET_NOT_FOUND: '您输入的资产不存在，请重新输入',

        BATCH_OPERATION_PART_FAIL: '批量操作时，部分下位机错误',
        DEVICE_NOT_REGISTERED: '未开启统一管理时，尝试修改数据或访问统一管理接口（除注册接口）',
        IP_NOT_MATCH: '统一管理平台访问时，与注册的管理平台IP不一致',
        BAD_SECRET: '统一管理平台访问时，secret不正确',
        NONE_MANAGEMENT_API: '统一管理平台访问时，访问了非管理接口',
        EDIT_STRATEGY_WHILE_APPLYING: '在下发策略时编辑了该设备的策略',

        FIREWALL_API_FAIL: '防火墙API调用失败',
        LEARNED_WHITELIST_ACTIVATION_FAIL: '防火墙自定义白名单启用/停用/删除失败',
        LEARNED_WHITELIST_OPERATION_WHILE_LEARNING: '防火墙自定义白名单正在学习，不能进行相关操作',
        LEARNED_WHITELIST_DELETING_ACTIVE_ITEM: '防火墙自定义白名单启用状态下不能删除',
        AUDITOR_PROTOCOL_FAIL: '协议审计获取失败，请检查审计相关配置',
        NO_AUDITOR_FOUND: '未关联审计',

        UN_ALLOWED_TO_EDIT_SYSTEM_TEMPLATE: '无法修改系统内置模板',
        UN_ALLOWED_TO_DELETE_SYSTEM_TEMPLATE: '无法删除系统内置模板',
        REPEATED_NAME_CATEGORY_TYPE_ERROR: '模板名称、资产类别、资产类型禁止重复',

        IP_TABLES_NULL_ERROR: '删除全部IP后，将无法访问，请重新配置',
        NTP_SETTING_ERROR: 'ntp校时失败，请确认目标主机是否开启校时服务',
        CITY_NOT_FOUND: '无法查询到该城市的地理位置信息',
    }


class CustomError(ErrorCode, APIException):
    def __init__(self, error=None, error_code=None, message=None, code=None):
        if not error_code:
            error_code = error['error']
        if not message:
            message = self.MESSAGE_MAP.get(error_code, '')
        detail = {'error': error_code, 'detail': message}

        super(CustomError, self).__init__(detail=detail, code=code)


class DeviceCommunicationError(APIException):
    """
    用于调用统一管理平台API返回的错误，格式为{code: 'msg'}，code和msg为统一管理平台返回的状态码和msg
    """
    status_code = 498
    default_detail = 'device communication error'
    default_code = 'device communication error'


class FirewallError(Exception):
    def __init__(self, message, status):

        # Call the base class constructor with the parameters it needs
        super().__init__(message)

        # Now for your custom code...
        self.status = status


class SNMPError(Exception):
    def __init__(self, message):
        super(SNMPError, self).__init__()
        self.message = message

    def __str__(self):
        return self.message


class CustomValidationError(ErrorCode, ValidationError):
    status_code = 499

    def __init__(self, error_code, message=None, code=None):
        if not message:
            message = self.MESSAGE_MAP.get(error_code, '')

        detail = {'error': error_code, 'detail': message}
        super(CustomValidationError, self).__init__(detail, code)


def flatten_error_message(messages: List[Dict[str, List]]) -> str:
    """
    需要将drf返回的字段校验错误信息整合到一条错误信息里
    [{'name': ['资产名称超过最大长度16'], 'ip': ['资产IP重复'], 'mac': ['资产MAC重复']}]
    :param messages:
    :return:
    """
    if isinstance(messages, dict):
        messages = [messages]
    message_list = []
    for msg in messages:
        for field, msgs in msg.items():
            for m in msgs:
                if m in ['Enter a valid IPv4 or IPv6 address.']:
                    m = AssetsField.IP_VALIDATOR_ERROR
                message_list.append(m)
    return ', '.join(message_list)


def custom_exception_handler(exc, context):
    """
    自定义400情况的报错信息，和综管自定义的499报错格式保持一致
    """
    response = exception_handler(exc, context)
    if response and response.status_code == 400:
        response.data = CustomError(
            error_code=CustomError.FIELD_ERROR,
            message=flatten_error_message(response.data)).detail
        response.status_code = 499
    return response
