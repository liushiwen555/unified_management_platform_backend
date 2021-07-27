from abc import ABC, abstractmethod
from typing import Optional, Dict, List

import regex as re

from base_app.models import Device

mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$')
ip_pattern = re.compile(
    r'^(((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))$')

error = str

"""
利用责任链模式对导入资产的数据进行校验
对每一项可导入数据（如资产名称，IP）编写单独的处理类，最后将所有的处理类串联成一条
责任链，将原始数据传入，并逐个检查是否满足数据格式要求
"""


class CheckerInterface(ABC):
    @abstractmethod
    def set_next(self, checker):
        pass

    @abstractmethod
    def check(self, device: Device, **kwargs) -> Optional[error]:
        pass


class Checker(CheckerInterface):
    _next_checker: CheckerInterface = None

    def set_next(self, checker: CheckerInterface) -> CheckerInterface:
        self._next_checker = checker
        return checker

    @abstractmethod
    def check(self, device: Device, **kwargs) -> Optional[error]:
        if self._next_checker:
            return self._next_checker.check(device, **kwargs)
        return None

    @classmethod
    def check_list(cls):
        checker = CheckName()
        checkers = [CheckCategory, CheckType, CheckBrand, CheckHardware,
                    CheckVersion, CheckIP, CheckMac, CheckResponsible,
                    CheckLocation, CheckValue, CheckDescription]

        checker_ = checker
        for c in checkers:
            checker_ = checker_.set_next(c())

        return checker


class CheckName(Checker):
    """
    检查资产名称是否在1-16的长度内，并且不重复
    """
    NAME_LENGTH_ERROR = '资产名称长度超过1-16的限制'
    NAME_DUPLICATE_ERROR = '资产名称重复'

    def check(self, device: Device, name_set=None, **kwargs) -> Optional[error]:
        name = str(device.name)
        if len(name) == 0 or len(name) > 16:
            return self.NAME_LENGTH_ERROR
        if name in name_set:
            return self.NAME_DUPLICATE_ERROR
        if Device.objects.filter(name=name).exists():
            return self.NAME_DUPLICATE_ERROR
        return super().check(device, **kwargs)


class CheckCategory(Checker):
    """
    资产类别要和综管定义好的类别匹配，如果没有填写资产类别，需要将字符串转为None，填写
    对了的资产类别要改为枚举
    """
    CATEGORY = [i[1] for i in Device.CATEGORY_CHOICE]
    CATEGORY_DICT = {i[1]: i[0] for i in Device.CATEGORY_CHOICE}
    CATEGORY_ERROR = '资产类别名称不匹配综合管理平台资产类别名称'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        category = device.category
        if not category:
            device.category = None
            return super().check(device, **kwargs)
        if category not in self.CATEGORY:
            return self.CATEGORY_ERROR
        device.category = self.CATEGORY_DICT[category]
        return super().check(device, **kwargs)


class CheckType(Checker):
    """
    资产类型要和综管定义好的类型匹配，如果没有填写资产类型，需要将字符串转为None，填写
    对了的资产类型要改为枚举
    """
    TYPES = [i[1] for i in Device.DEV_TEMP_TYPE_CHOICES]
    TYPES_DICT = {i[1]: i[0] for i in Device.DEV_TEMP_TYPE_CHOICES}
    TYPE_ERROR = '资产类型名称不匹配综合管理平台资产类型名称'
    CATEGORY_ERROR = '资产类型和资产类别不匹配'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        type_ = device.type
        if not type_:
            device.type = None
            return super().check(device, **kwargs)
        if type_ not in self.TYPES:
            return self.TYPE_ERROR
        device.type = self.TYPES_DICT[type_]
        if (device.category and device.type not in
                Device.CATEGORY_TYPES[device.category]):
            return self.CATEGORY_ERROR
        return super().check(device, **kwargs)


class CheckBrand(Checker):
    MAX_LENGTH = 10
    BRAND_ERROR = f'厂商名称长度超过{MAX_LENGTH}个字符'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        brand = str(device.brand)
        if len(brand) > self.MAX_LENGTH:
            return self.BRAND_ERROR
        return super().check(device, **kwargs)


class CheckHardware(Checker):
    MAX_LENGTH = 10
    HARDWARE_ERROR = f'型号长度超过{MAX_LENGTH}个字符'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        hardware = str(device.hardware)
        if len(hardware) > self.MAX_LENGTH:
            return self.HARDWARE_ERROR
        return super().check(device, **kwargs)


class CheckVersion(Checker):
    MAX_LENGTH = 10
    VERSION_ERROR = f'型号长度超过{MAX_LENGTH}个字符'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        version = str(device.version)
        if len(version) > self.MAX_LENGTH:
            return self.VERSION_ERROR
        return super().check(device, **kwargs)


class CheckIP(Checker):
    """
    检查ip地址是否符合格式要求并且不重复，ip地址不可为空
    """
    IP_MISS_ERROR = 'IP地址未提供'
    IP_VALIDATOR_ERROR = 'IP地址不符合格式要求'
    IP_DUPLICATE_ERROR = 'IP地址重复'

    def check(self, device: Device, ip_set=None, **kwargs) -> Optional[error]:
        ip = str(device.ip)
        if not ip:
            return self.IP_MISS_ERROR
        if not ip_pattern.match(ip):
            return self.IP_VALIDATOR_ERROR
        if ip in ip_set:
            return self.IP_DUPLICATE_ERROR
        if Device.objects.filter(ip=ip).exists():
            return self.IP_DUPLICATE_ERROR
        return super().check(device, **kwargs)


class CheckMac(Checker):
    """
    检查mac地址是否符合格式要求并且不重复，因为MAC地址可以为空，如果空就默认是对的
    """
    MAC_VALIDATOR_ERROR = 'MAC地址不符合格式要求'
    MAC_DUPLICATE_ERROR = 'MAC地址重复'

    def check(self, device: Device, mac_set=None, **kwargs) -> Optional[error]:
        mac = str(device.mac)
        if not mac:
            device.mac = None
            return super().check(device, **kwargs)
        if not mac_pattern.match(mac):
            return self.MAC_VALIDATOR_ERROR
        if mac in mac_set:
            return self.MAC_DUPLICATE_ERROR
        if Device.objects.filter(mac=mac).exists():
            return self.MAC_DUPLICATE_ERROR
        return super().check(device, **kwargs)


class CheckResponsible(Checker):
    MAX_LENGTH = 10
    RESPONSIBLE_ERROR = f'负责人长度超过{MAX_LENGTH}个字符'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        responsible_user = str(device.responsible_user)
        if len(responsible_user) > self.MAX_LENGTH:
            return self.RESPONSIBLE_ERROR
        return super().check(device, **kwargs)


class CheckLocation(Checker):
    MAX_LENGTH = 10
    LOCATION_ERROR = f'负责人长度超过{MAX_LENGTH}个字符'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        location = str(device.location)
        if len(location) > self.MAX_LENGTH:
            return self.LOCATION_ERROR
        return super().check(device, **kwargs)


class CheckValue(Checker):
    VALUES = [i[1] for i in Device.VALUE_CHOICE]
    VALUES_DICT = {i[1]: i[0] for i in Device.VALUE_CHOICE}
    VALUE_ERROR = '重要程度不匹配管管理平台重要程度'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        value = device.value
        if not value:
            device.value = None
            return super().check(device, **kwargs)
        if value not in self.VALUES:
            return self.VALUE_ERROR
        device.value = self.VALUES_DICT[value]
        return super().check(device, **kwargs)


class CheckDescription(Checker):
    MAX_LENGTH = 100
    DESCRIPTION_ERROR = f'备注长度超过{MAX_LENGTH}个字符'

    def check(self, device: Device, **kwargs) -> Optional[error]:
        description = str(device.description)
        if len(description) > self.MAX_LENGTH:
            return self.DESCRIPTION_ERROR
        return super().check(device, **kwargs)
