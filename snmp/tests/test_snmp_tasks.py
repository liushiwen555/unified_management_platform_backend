from datetime import timedelta

import pytest
from django.utils import timezone

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from snmp.factory_data import SNMPSettingFactory, SNMPTemplateFactory, \
    SNMPRuleFactory
from snmp.models import SNMPSetting, SNMPData
from snmp.tasks import check_should_snmp, _snmp_run


@pytest.mark.django_db
class TestTasks:
    def test_check_should_snmp(self):
        device = DeviceFactory.create(strategy_apply_status=1)
        device = Device.objects.get(id=device.id)

        assert not check_should_snmp(device)

        s = SNMPSettingFactory.create(device=device)
        s = SNMPSetting.objects.get(id=s.id)
        s.template = None
        s.save()
        device = Device.objects.get(id=device.id)

        assert not check_should_snmp(device)

        device.monitor = False
        device.save()
        device = Device.objects.get(id=device.id)
        assert not check_should_snmp(device)

        device.monitor = True
        device.save()
        s.template = SNMPTemplateFactory.create(rules=SNMPRuleFactory.create_batch(20))
        s.frequency = 1
        s.last_run_time = timezone.now() - timedelta(seconds=10000)
        s.save()
        device = Device.objects.get(id=device.id)
        assert check_should_snmp(device)

    def test_snmp_run(self):
        device = DeviceFactory.create(strategy_apply_status=1)
        d = Device.objects.get(id=device.id)
        s, _ = SNMPSetting.objects.get_or_create(device=d)
        s.template = SNMPTemplateFactory.create(rules=SNMPRuleFactory.create_batch(20))
        s.save()
        _snmp_run(d, timezone.now())

        assert SNMPData.objects.filter(device_id=d.id).exists()
