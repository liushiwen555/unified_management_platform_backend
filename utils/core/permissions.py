import logging

from rest_framework.permissions import BasePermission, SAFE_METHODS

from unified_management_platform.settings import ENABLE_PERMISSION
from user.models import ALL_GROUPS, Group, GROUP_ADMIN, GROUP_SECURITY_ENGINEER,\
    GROUP_CONFIG_ENGINEER

logger = logging.getLogger(__name__)


class IsAdmin(BasePermission):
    """
    仅允许管理员进行查看编辑修改等操作，其他人禁止一切操作
    """
    def has_permission(self, request, view):
        try:
            if not ENABLE_PERMISSION:
                return True
            if request.method in SAFE_METHODS:
                r_name = request.user.group.name
                return r_name in ALL_GROUPS
            else:
                return request.user.group.name == GROUP_ADMIN
        except (AttributeError, Group.DoesNotExist, Group.MultipleObjectsReturned):
            pass


class IsAllAdmin(BasePermission):
    """
    仅允许管理员进行查看编辑修改等操作，其他人禁止一切操作
    """

    def has_permission(self, request, view):
        try:
            if not ENABLE_PERMISSION:
                return True
            return request.user.group.name == GROUP_ADMIN
        except (AttributeError, Group.DoesNotExist, Group.MultipleObjectsReturned):
            pass


class IsSecurityEngineer(BasePermission):
    """
    仅允许安全工程师进行编辑修改等操作，其他所有人都可以进行浏览查询
    """

    def has_permission(self, request, view):
        try:
            if not ENABLE_PERMISSION:
                return True
            if request.method in SAFE_METHODS:
                r_name = request.user.group.name
                groups_list = ALL_GROUPS
                return r_name in groups_list
            else:
                return request.user.group.name == GROUP_SECURITY_ENGINEER
        except (AttributeError, Group.DoesNotExist, Group.MultipleObjectsReturned):
            pass


class IsConfiEngineer(BasePermission):
    """
    仅允许配置工程师进行编辑修改等操作，其他所有人都可以进行浏览查询
    """
    GROUP_NAME = GROUP_CONFIG_ENGINEER

    def has_permission(self, request, view):
        try:
            if not ENABLE_PERMISSION:
                return True
            if request.method in SAFE_METHODS:
                r_name = request.user.group.name
                groups_list = ALL_GROUPS
                return r_name in groups_list
            else:
                return request.user.group.name == self.GROUP_NAME
        except (AttributeError, Group.DoesNotExist, Group.MultipleObjectsReturned):
            pass


class IsSameUser(BasePermission):
    """
    要求查询的数据和token里的用户是同一个,但是管理员都可以看到
    """
    def has_object_permission(self, request, view, obj):
        if request.user.is_anonymous:
            return False
        return request.user.group.name == GROUP_ADMIN or request.user.id == obj.id
