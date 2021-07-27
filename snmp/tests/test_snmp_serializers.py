from typing import List, Dict

import pytest
from rest_framework.exceptions import ValidationError

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from snmp.factory_data import SNMPDataFactory
from snmp.models import SNMPData, SNMPSetting
from snmp.serializers import SNMPDataSerializer, SNMPSettingSerializer


@pytest.mark.django_db
class TestSNMPDataSerializer:
    @pytest.fixture(scope='function')
    def device(self) -> Device:
        return DeviceFactory.create_normal()

    @pytest.fixture(scope='function')
    def snmp_data(self, device):
        for i in range(10):
            SNMPDataFactory.create(
                device=device,
                system_info='Linux bolean 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64',
                disk_info=[
                    {'name': 'A', 'read': i + 2, 'write': i + 4},
                    {'name': 'B', 'read': i + 3, 'write': i + 3},
                ],
                process_count=i+100,
                network_usage=[
                    {'name': 'A', 'in': i+2, 'out': i+3},
                    {'name': 'B', 'in': i+3, 'out': i+2},
                ],
                network_in_speed=i+2,
                network_out_speed=i+3,
            )

    @pytest.fixture(scope='function')
    def first_data(self, snmp_data) -> SNMPData:
        return SNMPData.objects.first()

    @pytest.fixture(scope='function')
    def all_data(self, snmp_data) -> List[SNMPData]:
        return SNMPData.objects.all()

    @pytest.fixture(scope='function')
    def update_time(self, all_data) -> List:
        return [d.update_time for d in all_data[::-1]]

    def test_update_time(self, first_data: SNMPData, update_time):
        serializer = SNMPDataSerializer(first_data)
        assert serializer.data['update_time'] == update_time

    def test_disk_speed(self, first_data: SNMPData):
        serializer = SNMPDataSerializer(first_data)
        disk_info = serializer.data['disk_speed']

        write = {'data': [-(2*i+7) for i in range(10)]}
        read = {'data': [(2*i+5) for i in range(10)]}
        assert disk_info['write'] == write
        assert disk_info['read'] == read

    def test_process_count(self, first_data: SNMPData, all_data: List[SNMPData], update_time):
        serializer = SNMPDataSerializer(first_data)
        process_count = serializer.data['process_count']

        data = [i+100 for i in range(10)]

        assert process_count['data'] == data

    def test_disk_usage(self, first_data: SNMPData):
        serializer = SNMPDataSerializer(first_data)
        disk_usage = serializer.data['disk_usage']

        write = {
            'max': 25, 'avg': 16, 'current': 25
        }

        assert disk_usage['write'] == write
        read = {'max': 23, 'avg': 14, 'current': 23}

        assert disk_usage['read'] == read

    def test_network_speed(self, first_data: SNMPData, update_time):
        serializer = SNMPDataSerializer(first_data)
        network_speed = serializer.data['network_speed']

        in_ = {'data': [-(i+2) for i in range(10)]}
        out = {'data': [(i+3) for i in range(10)]}

        assert network_speed['in'] == in_
        assert network_speed['out'] == out

    def test_network_usage(self, first_data):
        serializer = SNMPDataSerializer(first_data)
        network_usage = serializer.data['network_usage']

        in_ = {
            'max': 23, 'avg': 14, 'current': 23
        }
        assert network_usage['in'] == in_

        out = {
            'max': 23, 'avg': 14, 'current': 23
        }
        assert network_usage['out'] == out


@pytest.mark.django_db
class TestSNMPSettingSerializer:
    @pytest.fixture(scope='function')
    def setting(self):
        device = DeviceFactory.create_normal()
        data = dict(
            device=device,
            version=SNMPSetting.SNMP_V1,
            status=True,
            auth=SNMPSetting.AUTH_MD5,
            priv=SNMPSetting.PRIV_3DES,
            community='1234'
        )
        return data

    @pytest.mark.parametrize('community', ['', '2' * 33])
    def test_community(self, setting, community):
        setting['community'] = community
        with pytest.raises(ValidationError):
            serializer = SNMPSettingSerializer(data=setting)
            serializer.is_valid(True)

        try:
            serializer = SNMPSettingSerializer(data=setting)
            serializer.is_valid(True)
        except ValidationError as e:
            assert 'community' in e.detail

    @pytest.mark.parametrize('username', ['2' * 33])
    def test_username(self, setting, username):
        setting['username'] = username
        with pytest.raises(ValidationError):
            serializer = SNMPSettingSerializer(data=setting)
            serializer.is_valid(True)

        try:
            serializer = SNMPSettingSerializer(data=setting)
            serializer.is_valid(True)
        except ValidationError as e:
            assert 'username' in e.detail

    @pytest.mark.parametrize('auth_password', ['1234', '2'*33])
    def test_auth_password(self, setting, auth_password):
        setting['auth_password'] = auth_password
        with pytest.raises(ValidationError):
            serializer = SNMPSettingSerializer(data=setting)
            serializer.is_valid(True)

        try:
            serializer = SNMPSettingSerializer(data=setting)
            serializer.is_valid(True)
        except ValidationError as e:
            assert 'auth_password' in e.detail

    @pytest.mark.parametrize('priv_password', ['1234', '2'*33])
    def test_priv_password(self, setting, priv_password):
        setting['priv_password'] = priv_password
        with pytest.raises(ValidationError):
            serializer = SNMPSettingSerializer(data=setting)
            serializer.is_valid(True)

        try:
            serializer = SNMPSettingSerializer(data=setting)
            serializer.is_valid(True)
        except ValidationError as e:
            assert 'priv_password' in e.detail


@pytest.mark.django_db
class TestSNMPNoneDataSerializer:
    @pytest.fixture(scope='function')
    def device(self) -> Device:
        return DeviceFactory.create_normal()

    @pytest.fixture(scope='function')
    def snmp_data(self, device):
        for i in range(10):
            SNMPDataFactory.create(
                device=device,
                system_runtime=None,
                system_info=None,
                disk_info=None,
                process_count=None,
                network_usage=None,
                network_in_speed=None,
                network_out_speed=None,
            )

    @pytest.fixture(scope='function')
    def first_data(self, snmp_data) -> SNMPData:
        return SNMPData.objects.first()

    @pytest.fixture(scope='function')
    def all_data(self, snmp_data) -> List[SNMPData]:
        return SNMPData.objects.all()

    @pytest.fixture(scope='function')
    def update_time(self, all_data) -> List:
        return [d.update_time for d in all_data[::-1]]

    @pytest.fixture(scope='function')
    def data(self, first_data: SNMPData) -> Dict:
        return SNMPDataSerializer(first_data).data

    def test_update_time(self, data: Dict, update_time):
        assert data['update_time'] == update_time

    def test_system_runtime(self, data: Dict):
        assert data['system_runtime'] is None

    def test_system_info(self, data: Dict):
        assert data['operation'] is None
        assert data['version'] is None

    def test_disk_speed(self, data: Dict):
        assert data['disk_speed'] is None

    def test_process_count(self, data: Dict):
        assert data['process_count'] is None

    def test_disk_usage(self, data: Dict):
        assert data['disk_usage'] is None

    def test_network_speed(self, data: Dict):
        assert data['network_speed'] is None

    def test_network_usage(self, data: Dict):
        assert data['network_usage'] is None

