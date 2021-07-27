import pytest

from utils.ip_search import ip_search, IPRecord


class TestIPSearch:
    @pytest.mark.parametrize('ip, country', [
        ['67.220.91.30', '美国'],
        ['133.242.187.207', '日本'],
        ['212.219.142.207', '英国'],
        ['176.192.102.130', '俄罗斯'],
        ['92.103.174.236', '法国'],
    ])
    def test_foreign_ip(self, ip, country):
        record = ip_search.search_ip_location(ip)

        assert record.country == country

    @pytest.mark.parametrize('ip, city', [
        ['175.45.20.138', '香港'],
        ['122.100.160.253', '澳门'],
        ['123.193.51.187', '台北'],
        ['122.146.176.41', 'Taichung']
    ])
    def test_special_ip(self, ip, city):
        record = ip_search.search_ip_location(ip)

        assert record.country == '中国'
        assert record.city == city

    @pytest.mark.parametrize('ip, province, city', [
        ['202.207.251.20', '山西', '太原'],
        ['123.138.162.112', '陕西', '西安']
    ])
    def test_shanxi_ip(self, ip, province, city):
        """
        陕西和山西IP划分
        """
        record = ip_search.search_ip_location(ip)

        assert record.province == province
        assert record.city == city
