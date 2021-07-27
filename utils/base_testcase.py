from typing import Union, Type, Dict

import pytest
from django.contrib.auth import get_user_model
from django.forms import model_to_dict
from django.urls import resolve
from pytest import fixture
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.test import APIClient

from utils.base_tezt_data import BaseFactory
from utils.core.permissions import IsAdmin, IsSecurityEngineer, IsConfiEngineer


User = get_user_model()


def _is_401_unauthorized(code):
    return status.HTTP_401_UNAUTHORIZED == code


def _is_403_forbidden(code):
    return status.HTTP_403_FORBIDDEN == code


def _is_auth_success(code):
    """
    code not in [401, 403], means auth success
    :param code:
    :return:
    """
    return code not in [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN]


@pytest.mark.django_db
class BaseTest:
    methods = ('get', 'post', 'put', 'patch', 'delete')
    admin_name = 'admin'
    engineer_name = 'engineer'
    auditor_name = 'auditor'
    right_password = 'Bl666666'
    wrong_password = 'Bl123456'
    ip = '125.2.26.94'
    url = None
    method = None
    list_size = 10
    page_size = 5
    status_map = {
        'anonymous': 401,
        'admin': 403,
        'engineer': 200,
        'auditor': 200,
        'local': 401
    }
    permission_map = {
        AllowAny: {
            'anonymous': _is_auth_success,
            'admin': _is_auth_success,
            'engineer': _is_auth_success,
            'auditor': _is_auth_success,
        },
        IsAdmin: {
            'anonymous': _is_401_unauthorized,
            'admin': _is_auth_success,
            'engineer': _is_403_forbidden,
            'auditor': _is_403_forbidden,
        },
        IsSecurityEngineer: {
            'anonymous': _is_401_unauthorized,
            'admin': _is_403_forbidden,
            'engineer': _is_auth_success,
            'auditor': _is_403_forbidden,
        },
        IsConfiEngineer: {
            'anonymous': _is_401_unauthorized,
            'admin': _is_403_forbidden,
            'engineer': _is_403_forbidden,
            'auditor': _is_auth_success,
        }
    }

    client = APIClient(enforce_csrf_checks=True, REMOTE_ADDR=ip)

    @fixture(scope='class')
    def post_data_map(self, *args, **kwargs):
        return {}

    @fixture(scope='class')
    def put_data_map(self, *args, **kwargs):
        return {}

    def anonymous(self):
        self.client.force_authenticate(user=None)

    def admin(self):
        admin_user = User.objects.get(username=self.admin_name)
        self.client.force_authenticate(user=admin_user)

    def engineer(self):
        engineer_user = User.objects.get(username=self.engineer_name)
        self.client.force_authenticate(user=engineer_user)

    def auditor(self):
        auditor_user = User.objects.get(username=self.auditor_name)
        self.client.force_authenticate(user=auditor_user)

    def check_permissions(self, url, url_permission_map):
        self.anonymous()
        res = self.client.options(url)
        allowed_method = [method.lower().strip() for method in res.get('allow').split(',')
                          if method.lower().strip() in self.methods]
        resolve_match = resolve(url)
        # permission_classes defined in detail_route or list_route action
        route_permission_classes = resolve_match.func.initkwargs.get('permission_classes')
        permission_action_classes = getattr(resolve_match.func.cls, 'permission_action_classes', None)
        permission_classes = getattr(resolve_match.func.cls, 'permission_classes', None)
        resolve_match_url_name = resolve_match.url_name

        for method in allowed_method:
            raw_permission, user_identity = url_permission_map.get(resolve_match_url_name)[method].values()
            get_permission = self._get_permission_classes(method, resolve_match, route_permission_classes,
                                                      permission_action_classes, permission_classes)
            # 测试对应 url，每个 method 所具有的权限
            assert raw_permission == get_permission
            if get_permission:
                self.tezt_permission(method, url, self.permission_map[get_permission], user_identity)

    def tezt_permission(self, method, url, status_map, user_identity, *args, **kwargs):
        for user, status_check_func in status_map.items():
            # 如果 user 具有对应权限，跳过
            if user in user_identity:
                pass
            else:
                # test user permission.
                getattr(self, user)()
                response = getattr(self.client, method.lower())(url, *args, **kwargs)
                assert_message = 'user:{}, url:{},method:{},status_code:{}, status_check_func:{}, resp:{}'.format(
                    user, url, method, response.status_code, status_check_func, response.content)
                assert (status_check_func(response.status_code), assert_message)

    def tezt_data(self, method, url, user, factory, data_map, *args, **kwargs):
        # authenticate.
        getattr(self, user)()
        for status_code, value_map in data_map.items():
            for field, values in value_map.items():
                for value in values:
                    data = factory.post_data().copy()
                    data.update(**{field: value})
                    # request and response.
                    response = getattr(self.client, method.lower())(url, data, 'json', *args, **kwargs)
                    assert response.status_code == status_code, '\n{}-{},{}: {}, {}'.format(response.status_code, status_code, field, value, response.data)

    @property
    def factory(self):
        return BaseFactory

    def _post_data(self):
        return model_to_dict(self.factory.build())

    def _get_permission_classes(self, method, resolve_match, route_permission_classes, permission_action_classes,
                                permission_classes):
        """
        通过不同处定义的permission_classes获取某method的permission_class,
        :param method:
        :param resolve_match: resolve(url) 得到的结果
        :param route_permission_classes: 定义在@list_route活detail_route中的permission_classes
        :param permission_action_classes: 定义在MultiActionConfViewSetMixin中的permission_classes
        :param permission_classes: 定义在view中的permission_classes
        :return:
        """

        if route_permission_classes:
            return route_permission_classes[0]
        elif permission_action_classes:
            try:
                return permission_action_classes[resolve_match.func.actions[method]][0]
            except KeyError:
                pass
        elif permission_classes:
            return permission_classes[0]

    def test_get_list(self, list_url, user='engineer', count=list_size):
        getattr(self, user)()
        response = self.client.get(list_url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['count'] == count
        response = self.client.get(list_url, {'page': 1, 'page_size': self.page_size})
        assert response.status_code == status.HTTP_200_OK
        assert response.data['count'] == count
        assert response.data['page_count'] == count/self.page_size

    def test_get_detail(self, detail_url, user='engineer'):
        getattr(self, user)()
        response = self.client.get(detail_url)
        assert response.status_code == status.HTTP_200_OK

    def test_get_detail_404(self, invalid_detail_url, user='engineer'):
        getattr(self, user)()
        response = self.client.get(invalid_detail_url)
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_post(self, list_url, post_data_map, user=engineer_name):
        self.tezt_data('post', list_url, user, self.factory, post_data_map)

    def test_put(self, detail_url, put_data_map, user=engineer_name):
        self.tezt_data('put', detail_url, user, self.factory, put_data_map)

    def test_delete(self, detail_url, invalid_detail_url, user=engineer_name):
        getattr(self, user)()
        response = self.client.delete(detail_url)
        assert response.status_code == status.HTTP_204_NO_CONTENT
        response = self.client.delete(invalid_detail_url)
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django
class BaseUser(object):
    anonymous = 'anonymous123'
    admin_name = 'admin123'
    engineer_name = 'engineer123'
    auditor_name = 'auditor123'
    config_engineer_name = 'config123'
    right_password = 'Bl@666666'


@pytest.mark.django_db
class MyBaseTest(object):
    client = APIClient()

    permission_map = {
        AllowAny: {
            'Anonymous': _is_auth_success,
            'Admin': _is_auth_success,
            'Engineer': _is_auth_success,
            'Auditor': _is_auth_success,
            'Config_Engineer': _is_auth_success,
        },
        IsAdmin: {
            'Anonymous': _is_401_unauthorized,
            'Admin': _is_auth_success,
            'Engineer': _is_403_forbidden,
            'Auditor': _is_403_forbidden,
            'Config_Engineer': _is_403_forbidden,
        },
        IsSecurityEngineer: {
            'Anonymous': _is_401_unauthorized,
            'Admin': _is_403_forbidden,
            'Engineer': _is_auth_success,
            'Auditor': _is_403_forbidden,
            'Config_Engineer': _is_403_forbidden,
        },
        IsConfiEngineer: {
            'Anonymous': _is_401_unauthorized,
            'Admin': _is_403_forbidden,
            'Engineer': _is_403_forbidden,
            'Auditor': _is_403_forbidden,
            'Config_Engineer': _is_auth_success,
        }
    }

    def _check_permissions(self, url: str, user_: User, code: int) -> bool:
        """
        检查用户是否有访问这个url的权限
        :param url: 访问url
        :param user_: 用户，分anonymous, admin, engineer, config_engineer, auditor
        :param code: 响应状态码
        :return 返回布尔值，用于assert判断
        """
        resolve_math = resolve(url)
        # list_route/detail_route权限
        route_permission_classes = resolve_math.func.initkwargs.get(
            'permission_classes')
        # 常规类里声明的权限
        permission_classes = getattr(resolve_math.func.cls,
                                     'permission_classes', [])

        for permission_class in permission_classes:
            if not self._get_right_authentication(user_, permission_class)(code):
                return False
        return True

    def _get_right_authentication(
            self,
            user_: User,
            permission_class:
            Type[Union[AllowAny, IsAdmin, IsSecurityEngineer, IsConfiEngineer]]):
        responses = self.permission_map[permission_class]

        if not user_:
            group = 'Anonymous'
        else:
            group = user_.groups.get().name

        return responses[group]


@pytest.mark.django_db
class BaseViewTest:
    @pytest.fixture(scope='function')
    def client(self):
        client = APIClient()

        return client

    @pytest.fixture(scope='function')
    def anonymous_client(self):
        client = APIClient(user=None)
        return client

    @pytest.fixture(scope='function')
    def admin_client(self):
        client = APIClient()
        client.force_authenticate(user=User.objects.get(
            username=BaseUser.admin_name))
        return client

    @pytest.fixture(scope='function')
    def config_client(self):
        client = APIClient()
        client.force_authenticate(user=User.objects.get(
            username=BaseUser.config_engineer_name))
        return client

    @pytest.fixture(scope='function')
    def audit_client(self):
        client = APIClient()
        client.force_authenticate(user=User.objects.get(
            username=BaseUser.auditor_name))
        return client

    @pytest.fixture(scope='function')
    def security_client(self):
        client = APIClient()
        client.force_authenticate(user=User.objects.get(
            username=BaseUser.engineer_name))
        return client

    @pytest.fixture(scope='function')
    def all_client(self, anonymous_client: APIClient, admin_client: APIClient,
                   audit_client: APIClient, security_client: APIClient,
                   config_client: APIClient) -> Dict[str, APIClient]:
        return {
            BaseUser.anonymous: anonymous_client,
            BaseUser.admin_name: admin_client,
            BaseUser.auditor_name: audit_client,
            BaseUser.engineer_name: security_client,
            BaseUser.config_engineer_name: config_client,
        }


all_user = [BaseUser.engineer_name, BaseUser.admin_name,
            BaseUser.auditor_name, BaseUser.config_engineer_name]


def could_create(user: str = None):
    res = [(BaseUser.anonymous, status.HTTP_401_UNAUTHORIZED)]
    for u in all_user:
        if u == user:
            res.append((u, status.HTTP_201_CREATED))
        else:
            res.append((u, status.HTTP_403_FORBIDDEN))

    return res


def could_delete(user: str = None):
    res = [(BaseUser.anonymous, status.HTTP_401_UNAUTHORIZED)]
    for u in all_user:
        if u == user:
            res.append((u, status.HTTP_204_NO_CONTENT))
        else:
            res.append((u, status.HTTP_403_FORBIDDEN))

    return res


def could_update(user: str = None):
    res = [(BaseUser.anonymous, status.HTTP_401_UNAUTHORIZED)]
    for u in all_user:
        if u == user:
            res.append((u, status.HTTP_200_OK))
        else:
            res.append((u, status.HTTP_403_FORBIDDEN))

    return res


# 登录用户即可查看
authenticate_read_only = pytest.mark.parametrize(
    'user, expect_code',
    [
        (BaseUser.anonymous, status.HTTP_401_UNAUTHORIZED),
        (BaseUser.admin_name, status.HTTP_200_OK),
        (BaseUser.config_engineer_name, status.HTTP_200_OK),
        (BaseUser.auditor_name, status.HTTP_200_OK),
        (BaseUser.engineer_name, status.HTTP_200_OK),
    ]
)

# 配置工程师才能修改
config_engineer_permission_create = pytest.mark.parametrize(
    'user, expect_code',
    could_create(BaseUser.config_engineer_name),
)

# 配置工程师才能删除
config_engineer_permission_delete = pytest.mark.parametrize(
    'user, expect_code',
    could_delete(BaseUser.config_engineer_name),
)

# 配置工程师才能修改
config_engineer_permission_update = pytest.mark.parametrize(
    'user, expect_code',
    could_update(BaseUser.config_engineer_name),
)


class ConfigEngineerPermission(object):
    # 登录用户即可查看
    authenticate_read_only = pytest.mark.parametrize(
        'user, expect_code',
        [
            (BaseUser.anonymous, status.HTTP_401_UNAUTHORIZED),
            (BaseUser.admin_name, status.HTTP_200_OK),
            (BaseUser.config_engineer_name, status.HTTP_200_OK),
            (BaseUser.auditor_name, status.HTTP_200_OK),
            (BaseUser.engineer_name, status.HTTP_200_OK),
        ]
    )

    # 配置工程师才能修改
    config_engineer_permission_201 = pytest.mark.parametrize(
        'user, expect_code',
        could_create(BaseUser.config_engineer_name),
    )

    # 配置工程师才能删除
    config_engineer_permission_204 = pytest.mark.parametrize(
        'user, expect_code',
        could_delete(BaseUser.config_engineer_name),
    )

    # 配置工程师才能修改
    config_engineer_permission_200 = pytest.mark.parametrize(
        'user, expect_code',
        could_update(BaseUser.config_engineer_name),
    )


class AdminPermission(object):
    authenticate_read_only = pytest.mark.parametrize(
        'user, expect_code',
        [
            (BaseUser.anonymous, status.HTTP_401_UNAUTHORIZED),
            (BaseUser.admin_name, status.HTTP_200_OK),
            (BaseUser.config_engineer_name, status.HTTP_200_OK),
            (BaseUser.auditor_name, status.HTTP_200_OK),
            (BaseUser.engineer_name, status.HTTP_200_OK),
        ]
    )
    # 管理员的增删改权限
    admin_permission_201 = pytest.mark.parametrize(
        'user, expect_code',
        could_create(BaseUser.admin_name),
    )

    admin_permission_204 = pytest.mark.parametrize(
        'user, expect_code',
        could_delete(BaseUser.admin_name),
    )

    admin_permission_200 = pytest.mark.parametrize(
        'user, expect_code',
        could_update(BaseUser.admin_name),
    )


# 管理员的增删改权限
admin_permission_create = pytest.mark.parametrize(
    'user, expect_code',
    could_create(BaseUser.admin_name),
)

admin_permission_delete = pytest.mark.parametrize(
    'user, expect_code',
    could_delete(BaseUser.admin_name),
)

admin_permission_update = pytest.mark.parametrize(
    'user, expect_code',
    could_update(BaseUser.admin_name),
)


class SecurityEngineerPermission(object):
    permission_read = pytest.mark.parametrize(
        'user, expect_code',
        [
            (BaseUser.anonymous, status.HTTP_401_UNAUTHORIZED),
            (BaseUser.admin_name, status.HTTP_200_OK),
            (BaseUser.config_engineer_name, status.HTTP_200_OK),
            (BaseUser.auditor_name, status.HTTP_200_OK),
            (BaseUser.engineer_name, status.HTTP_200_OK),
        ]
    )
    # 管理员的增删改权限
    permission_create = pytest.mark.parametrize(
        'user, expect_code',
        could_create(BaseUser.engineer_name),
    )

    permission_delete = pytest.mark.parametrize(
        'user, expect_code',
        could_delete(BaseUser.engineer_name),
    )

    permission_update = pytest.mark.parametrize(
        'user, expect_code',
        could_update(BaseUser.engineer_name),
    )
