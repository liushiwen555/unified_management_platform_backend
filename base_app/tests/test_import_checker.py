from typing import Set, Dict

import pytest

from base_app.device_import.checker import *
from base_app.device_import.excel_data import devices_from_file
from base_app.models import Device
from base_app.factory_data import DeviceFactory


@pytest.mark.django_db
class TestChecker:
    @pytest.fixture(scope='class')
    def checker_list(self) -> Checker:
        return Checker.check_list()

    @pytest.fixture(scope='function')
    def device(self) -> Device:
        data = {'name': '测试测试', 'category': '网络资产', 'type': '路由器',
                'brand': '华为', 'hardware': 'X60', 'version': '新版本',
                'ip': '192.168.1.1', 'mac': '11:22:33:44:55:99',
                'responsible_user': '谱久村11111', 'location': '麻布十番',
                'value': '高', 'description': ''}
        return Device(**data)

    @pytest.fixture(scope='function')
    def name_set(self) -> Set:
        return set()

    @pytest.fixture(scope='function')
    def ip_set(self) -> Set:
        return set()

    @pytest.fixture(scope='function')
    def mac_set(self) -> Set:
        return set()

    @pytest.fixture(scope='function')
    def kwargs(self) -> Dict[str, Set]:
        return {
            'name_set': set(),
            'ip_set': set(),
            'mac_set': set(),
        }

    def test_name(self, checker_list: Checker, device: Device,
                  kwargs: Dict[str, Set]):
        e = checker_list.check(device, **kwargs)
        assert e is None
        kwargs['name_set'].add(device.name)
        e = checker_list.check(device, **kwargs)
        assert e == CheckName.NAME_DUPLICATE_ERROR

        device.name = ''
        e = checker_list.check(device, **kwargs)
        assert e == CheckName.NAME_LENGTH_ERROR

        DeviceFactory.create_normal(name='上调麻布')
        device.name = '上调麻布'
        e = checker_list.check(device, **kwargs)
        assert e == CheckName.NAME_DUPLICATE_ERROR

    def test_category(self, checker_list: Checker, device: Device,
                      kwargs: Dict[str, Set]):
        device.category = 1
        e = checker_list.check(device, **kwargs)
        assert e == CheckCategory.CATEGORY_ERROR

        device.category = ''
        e = checker_list.check(device, **kwargs)
        assert device.category is None

    def test_type(self, checker_list: Checker, device: Device,
                  kwargs: Dict[str, Set]):
        device.type = '赤羽桥'
        e = checker_list.check(device, **kwargs)
        assert e == CheckType.TYPE_ERROR

        device.category = '网络资产'
        device.type = ''
        e = checker_list.check(device, **kwargs)
        assert e is None
        assert device.type is None

        device = self.device()
        device.type = '服务器'
        e = checker_list.check(device, **kwargs)
        assert e == CheckType.CATEGORY_ERROR

    def test_brand(self, checker_list: Checker, device: Device,
                   kwargs: Dict[str, Set]):
        device.brand = '123123123123'
        e = checker_list.check(device, **kwargs)
        assert e == CheckBrand.BRAND_ERROR

    def test_hardware(self, checker_list: Checker, device: Device,
                      kwargs: Dict[str, Set]):
        device.hardware = '123123123123'
        e = checker_list.check(device, **kwargs)
        assert e == CheckHardware.HARDWARE_ERROR

    def test_version(self, checker_list: Checker, device: Device,
                     kwargs: Dict[str, Set]):
        device.version = '123123123123'
        e = checker_list.check(device, **kwargs)
        assert e == CheckVersion.VERSION_ERROR

    def test_ip(self, checker_list: Checker, device: Device,
                kwargs: Dict[str, Set]):
        device.ip = '1.1233.12.12'
        e = checker_list.check(device, **kwargs)
        assert e == CheckIP.IP_VALIDATOR_ERROR

        device = self.device()
        device.ip = '1.1.1.1'
        kwargs['ip_set'].add(device.ip)
        e = checker_list.check(device, **kwargs)
        assert e == CheckIP.IP_DUPLICATE_ERROR
        DeviceFactory.create_normal(ip='1.2.2.2')

        device = self.device()
        device.ip = '1.2.2.2'
        e = checker_list.check(device, **kwargs)
        assert e == CheckIP.IP_DUPLICATE_ERROR

        device = self.device()
        device.ip = ''
        e = checker_list.check(device, **kwargs)
        assert e == CheckIP.IP_MISS_ERROR

    def test_mac(self, checker_list: Checker, device: Device,
                 kwargs: Dict[str, Set]):
        device.mac = ''
        e = checker_list.check(device, **kwargs)
        assert e is None
        assert device.mac is None

        device = self.device()
        device.mac = '11:22:33'
        e = checker_list.check(device, **kwargs)
        assert e == CheckMac.MAC_VALIDATOR_ERROR

        kwargs['mac_set'].add('11:22:33:44:55:66')
        device = self.device()
        device.mac = '11:22:33:44:55:66'
        e = checker_list.check(device, **kwargs)
        assert e == CheckMac.MAC_DUPLICATE_ERROR

        DeviceFactory.create_normal(mac='11:22:33:44:55:77')
        device = self.device()
        device.mac = '11:22:33:44:55:77'
        e = checker_list.check(device, **kwargs)
        assert e == CheckMac.MAC_DUPLICATE_ERROR

    def test_responsible(self, checker_list: Checker, device: Device,
                         kwargs: Dict[str, Set]):
        device.responsible_user = '麻布十番3町目3-3高荣大楼'
        e = checker_list.check(device, **kwargs)
        assert e == CheckResponsible.RESPONSIBLE_ERROR

    def test_location(self, checker_list: Checker, device: Device,
                      kwargs: Dict[str, Set]):
        device.location = '麻布十番3町目3-3高荣大楼'
        e = checker_list.check(device, **kwargs)
        assert e == CheckLocation.LOCATION_ERROR

    def test_value(self, checker_list: Checker, device: Device,
                   kwargs: Dict[str, Set]):
        device.value = ''
        e = checker_list.check(device, **kwargs)
        assert e is None
        assert device.value is None

        device = self.device()
        device.value = '大事'
        e = checker_list.check(device, **kwargs)
        assert e == CheckValue.VALUE_ERROR

    def test_description(self, checker_list: Checker, device: Device,
                         kwargs: Dict[str, Set]):
        device.description = '1'*101
        e = checker_list.check(device, **kwargs)
        assert e == CheckDescription.DESCRIPTION_ERROR

    def test_import_device(self, checker_list: Checker, device: Device):
        data = {
            '批量导入模板': [
                ['*资产名称', '资产类别', '资产类型', '厂商', '型号', '版本',
                 '*资产IP', '资产MAC', '负责人', '资产位置', '重要程度', '备注'],
                ['测试测试', '网络资产', '路由器', '华为', 'X60', '新版本',
                 '192.168.1.11.1', '11:22:33:44:55:99', '谱久村111',
                 '麻布十番', '高'],
                ['测试测试1', '网络资产', '路由器', '华为', 'X60', '新版本',
                 '192.168.1.11', '11:22:33:44:55:99', '谱久村111',
                 '麻布十番', '高'],
                ['测试测试1', '网络资产', '路由器', '华为', 'X60', '新版本',
                 '192.168.1.11', '11:22:33:44:55:99', '谱久村111',
                 '麻布十番', '高'],  # 资产名称重复
                ['测试测试3', '网络资产', '路由器', '华为', 'X60', '新版本',
                 '192.168.1.11', '11:22:33:44:55:99', '谱久村111',
                 '麻布十番', '高'],  # IP地址重复
                ['测试测试3', '网络资产', '路由器', '华为', 'X60', '新版本',
                 '192.168.1.111', '11:22:33:44:55:99', '谱久村111',
                 '麻布十番', '高']   # MAC地址重复
            ]}
        devices = devices_from_file(data)

        assert devices[0].error == CheckIP.IP_VALIDATOR_ERROR
        assert not devices[0].valid
        assert devices[1].valid

        assert not devices[2].valid
        assert devices[2].error == CheckName.NAME_DUPLICATE_ERROR

        assert not devices[3].valid
        assert devices[3].error == CheckIP.IP_DUPLICATE_ERROR

        assert not devices[4].valid
        assert devices[4].error == CheckMac.MAC_DUPLICATE_ERROR
