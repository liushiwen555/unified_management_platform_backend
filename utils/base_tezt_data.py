import factory
from factory import base, django


class MyDjangoOptions(django.DjangoOptions):
    def _build_default_options(self):
        return super(MyDjangoOptions, self)._build_default_options() + [
            base.OptionDefault('post_fields', [], inherit=True),
        ]


class SetNextSeqMixin:
    @classmethod
    def _setup_next_sequence(cls):
        try:
            return cls._meta.model.objects.latest('id').id + 1
        except cls._meta.model.DoesNotExist:
            return 1


class BaseFactory(factory.DjangoModelFactory):

    _options_class = MyDjangoOptions

    class Meta:
        abstract = True

    @classmethod
    def post_data(cls, fields=None):
        data = cls.stub().__dict__
        if fields:
            for key in list(data):
                if key not in fields:
                    data.pop(key)
        else:
            post_fields = cls._meta.post_fields
            if post_fields:
                for key in list(data):
                    if key not in post_fields:
                        data.pop(key)
            else:
                pass
        return data
