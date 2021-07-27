"""
字段校验错误信息
"""


class _BaseField(object):
    DESCRIPTION_LENGTH_EXCEED = '备注信息超过最大长度{max_length}'
    IP_DUPLICATE = 'IP地址重复'
    MAC_DUPLICATE = 'MAC地址重复'
    NAME_DUPLICATE = '名称重复'


_ = _BaseField


class UserField(_BaseField):
    verbose = '用户'

    USERNAME_DUPLICATE = '用户名已存在，请重新输入'
    DESCRIPTION_LENGTH_EXCEED = verbose + _.DESCRIPTION_LENGTH_EXCEED


class AssetsField(_BaseField):
    verbose = '资产'

    NAME_DUPLICATE = verbose + _.NAME_DUPLICATE
    IP_DUPLICATE = verbose + _.IP_DUPLICATE
    MAC_DUPLICATE = verbose + _.MAC_DUPLICATE
    IP_VALIDATOR_ERROR = verbose + 'IP地址格式错误'
    MAC_VALIDATOR_ERROR = verbose + 'MAC地址格式错误'

