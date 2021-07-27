import time

from django.contrib.auth import get_user_model
from django.contrib.auth import login, logout
from django.utils import timezone
from django.utils.timezone import localtime
from django.http.request import QueryDict
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.generics import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet

from user.models import UserExtension, GROUP_ADMIN, GROUP_AUDITOR, \
    GROUP_SECURITY_ENGINEER, GROUP_CONFIG_ENGINEER, ALL_GROUPS
from user.serializers import LoginSerializer, PasswordSerializer, \
    ModifyPasswordSerializer, UserSerializer, \
    UserCreateSerializer, UserUpdateSerializer
from user.filters import UserFilter
from utils.core.authentication import cipher
from utils.core.exceptions import CustomError
from utils.core.mixins import MultiActionConfViewSetMixin
from utils.core.permissions import IsAllAdmin, IsAdmin, IsSameUser
from utils.unified_redis import rs
from log.security_event import AbnormalLoginEvent

User = get_user_model()


class LoginView(GenericAPIView):
    authentication_classes = ()
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description:  post 方法，用户登录
          response:
            201:
              description: 用户登录
              response:
                examples1:
                    {
                    'token': auth_token,
                    'id': user.id,
                    'username': user.username,
                    'group': group_name,
                    'last_login': local time or None
                    }
            499:
              description: 登录出错
              response:
                examples1:
                    {'error': 1001}
        """
        data = request.data
        if isinstance(data, QueryDict):
            data = data.dict()
        data['ip'] = request.META['REMOTE_ADDR']
        serializer = LoginSerializer(data=data)
        event = AbnormalLoginEvent(username=request.data.get('username'))
        event.generate()
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        request.session['last_touch'] = time.time()
        data = {
            'token': cipher.encrypt(user.auth_token.key),
            'id': user.id,
            'username': user.username,
            'group': user.group.name,
            'last_login': localtime(user.last_login).isoformat() if user.last_login else None
        }
        return Response(data, status=status.HTTP_200_OK)


class LogoutView(APIView):
    """
    custom_swagger: 自定义 api 接口文档
    get:
      request:
        description:  get 方法，用户登出
      response:
        201:
          description: 用户登出
    """

    log_config = {
        'methods': ['GET'],
        'category': 1,
        'base_content': '登出审计平台',
    }

    def get(self, request, *args, **kwargs):
        ip = request.META['REMOTE_ADDR']
        username = getattr(request.user, 'username', 'anonymous')
        logout(request)
        if self.request.user and self.request.user.is_authenticated:
            self.request.user.auth_token.save()
            rs.delete(username)  # 清空身份认证时用于加密token的盐，参照utils.core.authentication.EncryptedTokenAuthentication
        return Response(status=status.HTTP_200_OK)


class ChangePasswordView(GenericAPIView):
    # permission_classes = (IsAuthenticated,)
    serializer_class = ModifyPasswordSerializer

    def post(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description:  更改密码
          response:
            201:
              description: 200
        """
        serializer = ModifyPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data['password']):
            raise CustomError({'error': CustomError.ORIGINAL_PSW_ERROR})
        user.set_password(serializer.validated_data['new_password1'])
        user.un_modify_passwd = False
        user.save(update_fields=['password', 'un_modify_passwd'])
        user_ext = UserExtension.objects.get(name=user.username)
        user_ext.last_change_psd = timezone.now()
        user_ext.save()
        # 修改密码之后要重新登录一下，否则部分情况下从session里无法得到当前用户是谁
        login(request, user)

        return Response(status=status.HTTP_200_OK)


class ResetPasswordView(GenericAPIView):
    permission_classes = (IsAllAdmin,)
    serializer_class = ModifyPasswordSerializer
    queryset = User.objects.filter(group__name__in=[
        GROUP_AUDITOR, GROUP_CONFIG_ENGINEER, GROUP_SECURITY_ENGINEER
    ])

    def post(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        post:
          request:
            description:  重置密码
          response:
            201:
              description: 200
        """
        user = get_object_or_404(self.queryset, pk=self.kwargs['pk'])
        serializer = ModifyPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        r = serializer.validated_data['password']
        if not request.user.check_password(r):
            raise CustomError({'error': CustomError.ADMIN_PSW_ERROR})
        user.set_password(serializer.validated_data['new_password1'])
        user.un_modify_passwd = False
        user.save(update_fields=['password', 'un_modify_passwd'])

        return Response(status=status.HTTP_200_OK)


class UserView(MultiActionConfViewSetMixin, ModelViewSet):
    permission_classes = (IsAllAdmin,)
    queryset = User.objects.filter(group__name__in=ALL_GROUPS).order_by('id')
    serializer_class = UserSerializer
    filter_class = UserFilter

    serializer_action_classes = {
        'list': UserSerializer,
        'create': UserCreateSerializer,
        'retrieve': UserSerializer,
        'update': UserUpdateSerializer,
        'partial_update': UserUpdateSerializer,
        'destroy': PasswordSerializer
    }
    permission_action_classes = {
        'retrieve': (IsSameUser, )
    }

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        ori_data = serializer.data
        last_login = localtime(instance.last_login).isoformat() if instance.last_login else ''
        ori_data['last_login'] = last_login
        return Response(ori_data)

    def get_queryset(self):
        # you can't delete or modify admin.
        if self.request.method == 'DELETE' or self.request.method == 'PATCH':
            return User.objects.filter(group__name__in=[
                GROUP_ADMIN, GROUP_AUDITOR, GROUP_CONFIG_ENGINEER,
                GROUP_SECURITY_ENGINEER
            ])
        return self.queryset

    def destroy(self, request, *args, **kwargs):
        """
        custom_swagger: 自定义 api 接口文档
        delete:
          request:
            description: delete 删除用户
            parameters:
               - name: password
                 in: query
                 description: 需要验证管理员密码
                 required: true
                 type: string
        """
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        # verify admin's password before delete user.
        serializer = PasswordSerializer(data=self.request.query_params)
        serializer.is_valid(raise_exception=True)
        if not self.request.user.check_password(serializer.validated_data['password']):
            raise CustomError({'error': CustomError.ADMIN_PSW_ERROR})
        # delete user extension at the same time.
        UserExtension.objects.filter(name=instance.username).delete()
        super(UserView, self).perform_destroy(instance)
