from typing import Dict, List

from pyexcel_xlsx import get_data

from base_app.device_import.checker import Checker
from base_app.models import Device


def get_devices(excel_file) -> List[Device]:
    json_data = get_data(excel_file)
    return devices_from_file(json_data)


def devices_from_file(data: Dict) -> List[Device]:
    raw_devices = []
    for k, v in data.items():
        if v[0] == ['*资产名称', '资产类别', '资产类型', '厂商', '型号', '版本',
                    '*资产IP', '资产MAC', '负责人', '资产位置', '重要程度', '备注']:
            raw_devices = v[1:]
            continue
        else:
            return []

    checker = Checker.check_list()
    name_set = set()
    mac_set = set()
    ip_set = set()
    devices = []
    for d in raw_devices:
        if not d:
            continue
        d = list_to_device(d)
        e = checker.check(d, name_set=name_set, ip_set=ip_set,
                          mac_set=mac_set)
        if not e:
            d.valid = True
            name_set.add(d.name)
            ip_set.add(d.ip)
            mac_set.add(d.mac)
        else:
            d.valid = False
            d.error = e
        devices.append(d)
    return devices


def list_to_device(data: List) -> Device:
    # 因为data长度不固定，所以使用了一个固定长度的data_，替代原来的data
    data_ = ['' for i in range(12)]
    for i in range(len(data)):
        data_[i] = data[i]

    device = {
        'name': data_[0],
        'category': data_[1],
        'type': data_[2],
        'brand': data_[3],
        'hardware': data_[4],
        'version': data_[5],
        'ip': data_[6],
        'mac': data_[7],
        'responsible_user': data_[8],
        'location': data_[9],
        'value': data_[10],
        'description': data_[11],
    }

    device = Device(**device)
    return device
