import sys

from django.apps import AppConfig
from django.conf import settings


# from user.serializers import cipher


class UserConfig(AppConfig):
    name = 'user'

    def ready(self):

        if 'makemigrations' in sys.argv or 'migrate' in sys.argv:
            return True

        from django.db.utils import IntegrityError
        from django.contrib.auth import get_user_model

        from user.models import UserExtension, GROUP_ADMIN, NON_ADMIN_GROUPS, \
            Group
        User = get_user_model()
        # create groups
        admin_group, created = Group.objects.get_or_create(name=GROUP_ADMIN)
        for g in NON_ADMIN_GROUPS:
            Group.objects.get_or_create(name=g)

        # create admin user.
        try:
            if not User.objects.filter(username='Admin123').exists():
                admin = User.objects.create_user(
                    'Admin123', password=settings.ADMIN_DEFAULT_PASSWORD,
                    group=admin_group)
                UserExtension.objects.create(
                    name='Admin123', description='系统内置的管理员，不可删除')
        except IntegrityError:
            pass
