import sys

from django.apps import AppConfig


class BaseAppConfig(AppConfig):
    name = 'base_app'

    def ready(self):
        if 'makemigrations' in sys.argv or 'migrate' in sys.argv:
            return True

        from django.db.utils import IntegrityError
        from base_app.models import StrategyTemplate, Device

        try:
            if not StrategyTemplate.objects.filter(type=Device.AUDITOR).exists():
                StrategyTemplate.objects.create(type=Device.AUDITOR, name='策略模板1')
            if not StrategyTemplate.objects.filter(type=Device.FIRE_WALL).exists():
                StrategyTemplate.objects.create(type=Device.FIRE_WALL, name='策略模板1')
        except IntegrityError:
            pass
