"""unified_management_platform URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
# from django.urls import path, include
from django.conf.urls import url, include
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

schema_view = get_schema_view(
    openapi.Info(
      title="drf_swagger_API",
      default_version='v1',
      description="综管文档描述",
    ),
    public=True,   # API 接口是否全部暴露出来
    permission_classes=(permissions.AllowAny,),  # 可查看 API 的权限
)


urlpatterns = [
    # url(r'^admin-3fsW4R1f/', admin.site.urls),
    url(r'^auditor/', include('auditor.urls')),
    url(r'^firewall/', include('firewall.urls')),
    url(r'^base/', include('base_app.urls')),
    url(r'^log/', include('log.urls')),
    url(r'^setting/', include('setting.urls')),
    url(r'^user/', include('user.urls')),
    url(r'^home/', include('home.urls')),
    url(r'^log-management/', include('unified_log.urls')),
    url(r'^snmp/', include('snmp.urls')),
    url(r'^statistic/', include('statistic.urls')),
]

if settings.DEBUG:
    urlpatterns.append(url(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'))

urlpatterns = [
    url(r'^api/v2/', include(urlpatterns)),
]
