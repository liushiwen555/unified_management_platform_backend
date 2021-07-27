import random

import factory
from django.contrib.auth import get_user_model

from user.models import UserExtension, Group
from utils.base_tezt_data import BaseFactory


User = get_user_model()


class UserFactory(BaseFactory):
    username = factory.Faker('user_name', locale='zh_CN')

    @factory.post_generation
    def password(self, create, extracted, **kwargs):
        if not create:
            # Simple build, do nothing.
            return
        if extracted and extracted.get('password'):
            # A password were passed in, use it.
            self.set_password(extracted.get('password'))
        else:
            self.set_password(factory.Faker('password').generate({}))

    @factory.post_generation
    def groups(self, create, extracted={}, **kwargs):
        if not create:
            # Simple build, do nothing.
            return
        if extracted and extracted.get('groups') in ['Engineer', 'Config_Engineer', 'Auditor']:
            # A name of group were passed in, use it.
            self.groups.add(Group.objects.get(name=extracted))
        else:
            self.groups.add(random.choice(Group.objects.filter(name__in=['Engineer', 'Config_Engineer', 'Auditor'])))

    @factory.post_generation
    def description(self, create, extracted, **kwargs):
        user_extension, created = UserExtension.objects.get_or_create(name=self.username)
        if not create:
            # Simple build, do nothing.
            return
        if extracted and extracted.get('description'):
            # A description were passed in, use it.
            user_extension.description = extracted.get('description')
            user_extension.save()
        else:
            user_extension.description = factory.Faker('text', locale='zh_CN', max_nb_chars=20).generate({})
            user_extension.save()

    class Meta:
        model = User
        django_get_or_create = ('username',)

    @classmethod
    def post_data(cls, fields=None):
        username = factory.Faker('user_name', locale='zh_CN').generate({})
        password = factory.Faker('password').generate({})
        groups = random.choice(['Engineer', 'Config_Engineer', 'Auditor'])
        description = factory.Faker('text', locale='zh_CN', max_nb_chars=200).generate({})
        data = {
            'username': username,
            'password1': password,
            'password2': password,
            'groups': groups,
            'description': description
        }
        return data

    @classmethod
    def create_user(cls, username, **kwargs):
        kwargs['password'] = kwargs.pop('password1')
        return cls(username=username, extracted=kwargs)
