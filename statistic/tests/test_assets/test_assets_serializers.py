import pytest
from django.utils import timezone

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from log.models import DeviceAllAlert, SecurityEvent
from statistic.models import IPDistribution
from statistic.serializers import DeviceDistributionSerializer, \
    IPDistributionHelper
from utils.helper import get_today


@pytest.mark.django_db
class TestDeviceDistribution:
    def test_count(self):
        DeviceFactory.create_batch_normal(20)
        data = DeviceDistributionSerializer(Device.objects.all())
        data = data.get_count()

        assert data[Device.CATEGORY_Communication] == Device.objects.filter(
            category=Device.CATEGORY_Communication).count()
        assert data[Device.CATEGORY_Control] == Device.objects.filter(
            category=Device.CATEGORY_Control).count()
        assert data[Device.CATEGORY_Sever] == Device.objects.filter(
            category=Device.CATEGORY_Sever).count()
        assert data[Device.CATEGORY_Security] == Device.objects.filter(
            category=Device.CATEGORY_Security).count()

    def test_risk(self):
        """
        有关联安全事件或安全威胁的资产数量
        """
        data = DeviceDistributionSerializer(Device.objects.all()).get_risk()

        device1 = DeviceAllAlert.objects.filter(
            device__category=Device.CATEGORY_Sever,
            status_resolved=DeviceAllAlert.STATUS_UNRESOLVED).values_list(
            'device__id').distinct('device__id').order_by('device__id')
        device2 = SecurityEvent.objects.filter(
            device__category=Device.CATEGORY_Sever,
            status_resolved=SecurityEvent.STATUS_UNRESOLVED).values_list(
            'device__id').distinct('device__id').order_by('device__id')
        device = len(set(device1) | set(device2))

        assert data[Device.CATEGORY_Sever] == device

    def test_add(self):
        data = DeviceDistributionSerializer(Device.objects.all()).get_add()

        assert data[Device.CATEGORY_Sever] == Device.objects.filter(
            created_at__gte=get_today(), category=Device.CATEGORY_Sever).count()
        assert data[Device.CATEGORY_Communication] == Device.objects.filter(
            created_at__gte=get_today(),
            category=Device.CATEGORY_Communication).count()
        assert data[Device.CATEGORY_Control] == Device.objects.filter(
            created_at__gte=get_today(),
            category=Device.CATEGORY_Control).count()
        assert data[Device.CATEGORY_Security] == Device.objects.filter(
            created_at__gte=get_today(),
            category=Device.CATEGORY_Security).count()

    def test_performance(self):
        """
        性能监控的数量
        """
        data = DeviceDistributionSerializer(
            Device.objects.all()).get_performance()

        for category in Device.CATEGORY_CHOICE:
            category = category[0]
            assert data.get(category, 0) == Device.objects.filter(
                category=category, monitor=True).count()

    def test_log(self):
        """
        日志监控的数量
        """
        data = DeviceDistributionSerializer(
            Device.objects.all()).get_log()

        for category in Device.CATEGORY_CHOICE:
            category = category[0]
            assert data.get(category, 0) == Device.objects.filter(
                category=category, log_status=True).count()

    def test_online(self):
        """
        在线资产的数量
        """
        data = DeviceDistributionSerializer(Device.objects.all()).get_online()

        for category in Device.CATEGORY_CHOICE:
            category = category[0]
            assert data.get(category, 0) == Device.objects.filter(
                category=category, status=Device.ONLINE).count()

    def test_responsible_user(self):
        DeviceFactory.create_batch_normal(10, category=Device.CATEGORY_Sever,
                                          responsible_user='Mizuki')
        DeviceFactory.create_batch_normal(8, category=Device.CATEGORY_Sever,
                                          responsible_user='Ayumi')
        DeviceFactory.create_batch_normal(6, category=Device.CATEGORY_Sever,
                                          responsible_user='Masaki')

        data = DeviceDistributionSerializer(
            Device.objects.all()).get_responsible_user()

        assert data[Device.CATEGORY_Sever] == ['Mizuki', 'Ayumi', 'Masaki']


@pytest.mark.django_db
class TestAssetsIPSerializer:
    def previous_ip_distribution(self) -> IPDistribution:
        distribution = {
            '192.168.1.1/24': ['192.168.1.1', '192.168.1.2'],
            '192.168.3.1/24': ['192.168.3.1'],
            '172.16.23.1/24': ['172.16.23.2', '172.16.23.3'],
            '10.0.3.1/24': ['10.0.3.2'],
        }
        dist, _ = IPDistribution.objects.get_or_create(id=1)
        dist.ips = distribution
        dist.update_time = timezone.now()
        dist.save()
        return dist

    def test_ip_distribution_helper(self):
        self.previous_ip_distribution()
        ips = [
            '192.168.1.1', '192.168.1.2', '192.168.3.1', '172.16.23.3',
            '10.0.4.1', '10.0.2.1',  # 新增的
            # '172.16.23.2', '10.0.3.2',  # 删除的
        ]
        helper = IPDistributionHelper(ips)
        helper.analyze_distribution()

        assert helper.count == 6
        helper.distribution['192.168.1.1/24']['used'].sort()
        assert helper.ip_distribution == {
            '192.168.1.1/24': {
                'gateway': '192.168.1.1/24', 'ip_count': 2, 'update_count': 0,
                'used': ['192.168.1.1', '192.168.1.2'], 'updated': []
            },
            '192.168.3.1/24': {
                'gateway': '192.168.3.1/24', 'ip_count': 1, 'update_count': 0,
                'used': ['192.168.3.1'], 'updated': [],
            },
            '10.0.4.1/24': {
                'gateway': '10.0.4.1/24', 'ip_count': 1, 'update_count': 1,
                'used': ['10.0.4.1'], 'updated': ['10.0.4.1'],
            },
            '10.0.2.1/24': {
                'gateway': '10.0.2.1/24', 'ip_count': 1, 'update_count': 1,
                'used': ['10.0.2.1'], 'updated': ['10.0.2.1'],
            },
            '172.16.23.1/24': {
                'gateway': '172.16.23.1/24', 'ip_count': 1, 'update_count': 1,
                'used': ['172.16.23.3'], 'updated': ['172.16.23.2'],
            }
        }
        assert helper.segments == 5
