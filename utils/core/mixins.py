from utils.core.exceptions import CustomError
from utils.core.permissions import IsConfiEngineer


class MultiActionConfViewSetMixin:
    """
    重写获取相应配置的方法，需要在view中写对应的dict，映射action name(key)到配置的class(value)
    以serializer为例
    i.e.:

    class MyViewSet(MultiSerializerViewSetMixin, ViewSet):
        serializer_class = MyDefaultSerializer
        serializer_action_classes = {
           'list': MyListSerializer,
           'my_action': MyActionSerializer,
        }

        @action
        def my_action:
            ...

    如果没有找到action的入口，则回退到常规的get_serializer_class
    lookup: self.serializer_class, MyDefaultSerializer.
    配置对应的dict为
    get_serializer_class() : serializer_action_classes
    get_permission_class() : permission_action_classes

    Thanks gonz: http://stackoverflow.com/a/22922156/11440
    """
    serializer_action_classes = {}
    permission_action_classes = {}

    def get_serializer_class(self):

        try:
            return self.serializer_action_classes[self.action]
        except (KeyError, AttributeError):
            return super(MultiActionConfViewSetMixin, self).get_serializer_class()

    def get_permissions(self):

        try:
            return [permission() for permission in self.permission_action_classes[self.action]]
        except (KeyError, AttributeError):
            return super(MultiActionConfViewSetMixin, self).get_permissions()


class UniqueAttrMixin:
    """
    some attr should be unique under a device or template, override the save method
    to ensure that.
    """

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):

        unique_attr_list = self.unique_attr_list
        for attr in unique_attr_list:
            pairs = self.__class__.objects.exclude(pk=self.pk).values_list('device', 'template', attr)
            pair = (
                self.device.id if self.device else None, self.template.id if self.template else None,
                getattr(self, attr))
            if pair in pairs:
                err_code = CustomError.DEVICE_AND_RULE_ID_EXIST_ERROR
                if 'ip' in attr:
                    err_code = CustomError.IP_REPEAT_ERROR
                if 'mac' in attr:
                    err_code = CustomError.MAC_REPEAT_ERROR
                raise CustomError({'error': err_code, 'msg': attr})
        super(UniqueAttrMixin, self).save(force_insert=force_insert, force_update=force_update,
                                          using=using, update_fields=update_fields)


class UniqueModelMixin:
    """"
    some model should be unique under a device or template, override the save method
    to ensure that.
    """
    def save(self, force_insert=False, force_update=False, using=None, update_fields=None):
        if self.__class__.objects.filter(device_id=self.device_id,
                                         template_id=self.template_id).exists() and not self.pk:
            # 确保表中只有一条记录
            pass
        else:
            return super(UniqueModelMixin, self).save(force_insert=force_insert,
                                                      force_update=force_update,
                                                      using=using,
                                                      update_fields=update_fields)


class ConfiEngineerPermissionsMixin(MultiActionConfViewSetMixin):
    """
    Auditor can access only save methods, while Engineer can access all
    """

    permission_classes = (IsConfiEngineer,)


class MultiMethodAPIViewMixin:
    """
    重写获取相应配置的方法，需要在view中写对应的dict，映射method name(key)到配置的class(value)
    以serializer为例
    i.e.:

    class MyViewSet(MultiSerializerViewSetMixin, ViewSet):
        serializer_class = MyDefaultSerializer
        serializer_method_classes = {
           'get': MyListSerializer,
           'post': MyActionSerializer,
        }

    如果没有找到method的入口，则回退到常规的get_serializer_class
    lookup: self.serializer_class, MyDefaultSerializer.
    配置对应的dict为
    get_serializer_class() : serializer_action_classes
    get_permission_class() : permission_action_classes

    Thanks gonz: http://stackoverflow.com/a/22922156/11440
    """
    serializer_method_classes = {}
    permission_method_classes = {}

    def get_serializer_class(self):
        try:
            return self.serializer_method_classes[self.request.method]
        except (KeyError, AttributeError):
            return super().get_serializer_class()

    def get_permissions(self):

        try:
            return [permission() for permission in self.permission_method_classes[self.request.method]]
        except (KeyError, AttributeError):
            return super().get_permissions()
