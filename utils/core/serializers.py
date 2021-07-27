from django.utils.functional import cached_property
from rest_framework import serializers
from rest_framework.validators import UniqueTogetherValidator
from drf_yasg import openapi


class UniqueTogetherModelSerializer(serializers.ModelSerializer):

    def get_unique_together_validators(self):
        """
                Determine a default set of validators for any unique_together constraints.
                """
        model_class_inheritance_tree = (
                [self.Meta.model] +
                list(self.Meta.model._meta.parents.keys())
        )

        # The field names we're passing though here only include fields
        # which may map onto a model field. Any dotted field name lookups
        # cannot map to a field, and must be a traversal, so we're not
        # including those.
        field_names = {
            field.source for field in self._writable_fields
            if (field.source != '*') and ('.' not in field.source)
        }

        # Note that we make sure to check `unique_together` both on the
        # base model class, but also on any parent classes.
        validators = []
        for parent_class in model_class_inheritance_tree:
            for unique_together in parent_class._meta.unique_together:
                validator = UniqueTogetherValidator(
                    queryset=parent_class._default_manager,
                    fields=unique_together
                )
                validators.append(validator)
        return validators

    @cached_property
    def _writable_fields(self):
        return [
            field for field in self.fields.values()
        ]


class ErrorSerializer(serializers.Serializer):
    error = serializers.IntegerField(label='错误代码', read_only=True)
    detail = serializers.CharField(label='错误详情', read_only=True)

    def update(self, instance, validated_data):
        pass

    def create(self, validated_data):
        pass


def get_schema_response(detail, example=None):
    return openapi.Response(detail, ErrorSerializer, example)