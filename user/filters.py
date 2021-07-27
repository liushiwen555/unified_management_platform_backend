from django_filters import rest_framework as filters

from utils.core.filters import BaseFilters
from user.models import User


class UserFilter(BaseFilters):
    group = filters.CharFilter('group__name', lookup_expr='exact',
                               help_text='传递用户组的英文名字')
    is_active = filters.BooleanFilter('is_active', lookup_expr='exact',
                                      help_text='传递bool的状态')

    class Meta:
        model = User
        fields = ('group', 'is_active')
