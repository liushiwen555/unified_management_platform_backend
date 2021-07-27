import pytest

from base_app.factory_data import DeviceFactory
from base_app.models import Device
from setting.models import Location


@pytest.fixture(scope='session')
def django_db_setup(django_db_setup, django_db_blocker):
    with django_db_blocker.unblock():
        d = DeviceFactory.create_normal(
            type=Device.AUDITOR, register_status=Device.REGISTERED
        )
        Location.objects.get_or_create(id=1)