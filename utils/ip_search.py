import json
import os
from typing import Dict, Optional

from IP2Location import IP2Location
from django.conf import settings


SHAANXI = 'SHAANXI'


def _load_geography():
    with open(os.path.join(settings.MEDIA_ROOT, 'chinese_geo.json'), 'r') as f:
        data = json.load(f)
    return data


def _load_foreign_country():
    with open(os.path.join(settings.MEDIA_ROOT,
                           'foreign_country.json'), 'r') as f:
        data = json.load(f)
    return data


class IPRecord(object):
    def __init__(self, ip, country=None, province=None, city=None,
                 latitude=None, longitude=None):
        self.ip = ip
        self.country = country
        self.province = province
        self.city = city
        self.latitude = latitude
        self.longitude = longitude


class IPSearch(object):
    _geo_data = _load_geography()
    _foreign_country = _load_foreign_country()
    _ip_search: IP2Location = IP2Location(os.path.join(
        settings.MEDIA_ROOT, 'IP2LOCATION-LITE-DB5.BIN'))
    chinese = ['China', 'Taiwan (Province of China)', 'Macao', 'Hong Kong']

    def search_ip_location(self, ip) -> Optional[IPRecord]:
        record = self._ip_search.get_all(ip)
        if not record:
            IPRecord(None, None, None, None, None, None)
        country = record.country_long
        if self.is_chinese(country):
            country = '中国'
            location = self.get_location(record)
            province = location['p']
            city = location['c']
            latitude = location['lat']
            longitude = location['long']
        else:
            country = self._foreign_country.get(country, country)
            province = record.region
            city = record.city
            latitude = record.latitude
            longitude = record.longitude
        return IPRecord(ip, country, province, city, latitude, longitude)

    def is_chinese(self, country):
        return country in self.chinese

    def get_location(self, record) -> Dict:
        """
        根据英文省份、英文城市，返回中文省份，中文城市，以及经纬度
        :param province_en: 英文省份
        :param city_en: 英文城市
        :return:
        {'p': xx, 'c':xx, 'lat': xxx, 'long': xxx}
        """
        province_en = record.region
        city_en = record.city
        default = {'p': province_en, 'c': city_en,
                   'lat': record.latitude, 'long': record.longitude}
        if province_en == 'Shaanxi':
            province_en = SHAANXI
        if province_en not in self._geo_data:
            return default
        cities = list(self._geo_data[province_en].values())
        if cities:
            default['p'] = cities[0]['p']
        res = self._geo_data[province_en].get(city_en, default)

        return res


ip_search = IPSearch()


class CitySearch(object):
    _city_geo = None

    @classmethod
    def search(cls, city):
        if not cls._city_geo:
            cls._load()
        return cls._city_geo.get(city)

    @classmethod
    def _load(cls):
        with open(os.path.join(settings.MEDIA_ROOT, 'city_geo.json'), 'r') as f:
            cls._city_geo = json.load(f)
