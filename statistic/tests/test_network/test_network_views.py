import pytest
from django.utils import timezone
from rest_framework.test import APIClient
from django.urls import reverse

from utils.base_testcase import BaseViewTest
from auditor.bolean_auditor.process_protocol import PortRank, ProtocolIPRank
from auditor.bolean_auditor.synchronize import AuditorProtocolTraffics
from base_app.models import Device
from base_app.factory_data import DeviceFactory


@pytest.fixture(scope='function')
def auditor() -> Device:
    device = DeviceFactory.create_normal(
        category=Device.CATEGORY_Security,
        type=Device.AUDITOR,
        register_status=Device.REGISTERED
    )
    return Device.objects.get(id=device.id)


class TestPortTopFiveView(BaseViewTest):
    def test_port_top_five(self, config_client: APIClient):
        PortRank.clean()
        port_rank = PortRank(timezone.now())
        port_rank._data = {
            'src_port': {'222': 100, '333': 80, '444': 50, '555': 30, '666': 20,
                         '777': 10},
            'dst_port': {'222': 100, '333': 80, '444': 50, '555': 30, '666': 20,
                         '777': 10}
        }
        port_rank.save()

        response = config_client.get(reverse('port-top-five')).json()
        assert response['src_port'] == [
            {'port': '222', 'count': 100},
            {'port': '333', 'count': 80},
            {'port': '444', 'count': 50},
            {'port': '555', 'count': 30},
            {'port': '666', 'count': 20},
            {'port': '其他', 'count': 10}
        ]


class TestIPTopFiveView(BaseViewTest):
    def test_ip_top_five(self, config_client: APIClient):
        ProtocolIPRank.clean()
        ip_rank = ProtocolIPRank(timezone.now())
        ip_rank._data = {
            'src_ip': {'127.0.0.1': 100, '127.0.0.2': 80, '127.0.0.3': 50,
                       '127.0.0.4': 30, '127.0.0.5': 20, '127.0.0.6': 10},
            'dst_ip': {'127.0.0.1': 100, '127.0.0.2': 80, '127.0.0.3': 50,
                       '127.0.0.4': 30, '127.0.0.5': 20, '127.0.0.6': 10}
        }
        ip_rank.save()
        response = config_client.get(reverse('ip-top-five')).json()
        assert response['src_ip'] == [
            {'ip': '127.0.0.1', 'count': 100, 'percent': 100},
            {'ip': '127.0.0.2', 'count': 80, 'percent': 80},
            {'ip': '127.0.0.3', 'count': 50, 'percent': 50},
            {'ip': '127.0.0.4', 'count': 30, 'percent': 30},
            {'ip': '127.0.0.5', 'count': 20, 'percent': 20},
        ]


class TestProtocolTraffic(BaseViewTest):
    def test_protocol_traffic(self, config_client: APIClient, auditor: Device):
        sync = AuditorProtocolTraffics(auditor)
        data = sync.request_for_data()
        update_time = [i['time'] for i in data[:48]]

        response = config_client.get(reverse('protocol-traffics')).json()
        assert update_time == response['update_time']
