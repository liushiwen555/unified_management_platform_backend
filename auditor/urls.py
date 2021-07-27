# from django.urls import path, include
from django.conf.urls import url, include
from rest_framework_extensions.routers import ExtendedSimpleRouter

from auditor import views

app_name = 'auditor'

router = ExtendedSimpleRouter()
device_router = router.register('device', views.AuditDeviceView, basename='device')
device_router.register('whitelist',
                       views.DeviceWhiteListStrategyView,
                       basename='white-lists',
                       parents_query_lookups=['device'])
device_router.register('blacklist',
                       views.DeviceBlackListStrategyView,
                       basename='black-lists',
                       parents_query_lookups=['device'])


template_router = router.register('template', views.AuditTemplateView, basename='template')
template_router.register('whitelist',
                         views.TempWhiteListStrategyView,
                         basename='white-lists',
                         parents_query_lookups=['template'])
template_router.register('blacklist',
                         views.TempBlackListStrategyView,
                         basename='black-lists',
                         parents_query_lookups=['template'])

urlpatterns = [
    url(r'^', include(router.urls)),
]
