import os
from os import path
from abc import ABC, abstractmethod

import django
from django.conf import settings
from pyexcel_xlsx import get_data

os.environ.setdefault("DJANGO_SETTINGS_MODULE",
                      "unified_management_platform.settings")
django.setup()

from log.models import DeviceAllAlert
from auditor.models import AuditorBlackList


class Loadable(ABC):
    @classmethod
    @abstractmethod
    def load(cls):
        pass


class LoadDeviceAlert(Loadable):
    LEVEL = 2
    CATEGORY = 4
    TYPE = 5
    SEC_DESC = 6
    SUGGEST_DESC = 13
    SID = 22


    LEVEL_DICT = {
        '低级': DeviceAllAlert.LEVEL_LOW,
        '中级': DeviceAllAlert.LEVEL_MEDIUM,
        '高级': DeviceAllAlert.LEVEL_HIGH,
    }

    CATEGORY_DICT = {
        d[1]: d[0] for d in DeviceAllAlert.EVENT_CATEGORY_CHOICE
    }

    TYPE_DICT = {
        d[1]: d[0] for d in DeviceAllAlert.TYPE_CHOICES
    }

    @classmethod
    def load(cls):
        excel_data = get_data(path.join(
            settings.MEDIA_ROOT,
            'V2.2【综合管理平台】安全威胁内容及格式-20201210-最新（990条直接使用的数据）.xlsx'
        ))
        sheet = None
        for k, v in excel_data.items():
            sheet = v
        cls.process(sheet[1:])

    @classmethod
    def process(cls, data_list):
        for data in data_list:
            alert = dict(
                level=cls.LEVEL_DICT[data[cls.LEVEL]],
                category=cls.CATEGORY_DICT[data[cls.CATEGORY].strip()],
                type=cls.TYPE_DICT[data[cls.TYPE].strip()],
                sec_desc=data[cls.SEC_DESC],
                suggest_desc=data[cls.SUGGEST_DESC],
                status_resolved=DeviceAllAlert.STATUS_RESOLVED
            )
            DeviceAllAlert.objects.create(**alert)


if __name__ == '__main__':
    LoadDeviceAlert.load()