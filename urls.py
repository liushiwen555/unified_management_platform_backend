# from django.urls import path, include
from django.conf.urls import url, include
from rest_framework_extensions.routers import ExtendedSimpleRouter

from firewall import views

app_name='firewall'

router = ExtendedSimpleRouter()
device_router = router.register('device', views.FirewallDeviceView, basename='device')

device_router.register('whitelist',
                       views.DeviceWhiteListStrategyView,
                       basename='white-lists',
                       parents_query_lookups=['device'])
device_router.register('learned-whitelist',
                       views.LearnedWhiteListStrategyView,
                       basename='learned-white-lists',
                       parents_query_lookups=['device'])
device_router.register('blacklist',
                       views.DeviceBlackListStrategyView,
                       basename='black-lists',
                       parents_query_lookups=['device'])
device_router.register('ip-mac-bond',
                       views.DeviceIPMACBondStrategyView,
                       basename='ip-mac-bond',
                       parents_query_lookups=['device'])
device_router.register('base-firewall',
                       views.DeviceBaseFirewallStrategyView,
                       basename='base-firewall',
                       parents_query_lookups=['device'])
device_router.register('modbus',
                       views.DeviceModbusStrategyView,
                       basename='modbus',
                       parents_query_lookups=['device'])
device_router.register('s7',
                       views.DeviceS7StrategyView,
                       basename='s7',
                       parents_query_lookups=['device'])
# router.register('sec-event', views.FirewallSecEventView, basename='sec-alert')
router.register('sys-event', views.FirewallSysEventView, basename='sys-alert')

template_router = router.register('template', views.FirewallTemplateView, basename='template')
template_router.register('whitelist',
                         views.TempWhiteListStrategyView,
                         basename='white-lists',
                         parents_query_lookups=['template'])
template_router.register('blacklist',
                         views.TempBlackListStrategyView,
                         basename='black-lists',
                         parents_query_lookups=['template'])
template_router.register('ip-mac-bond',
                         views.TempIPMACBondStrategyView,
                         basename='ip-mac-bond',
                         parents_query_lookups=['template'])

template_router.register('base-firewall',
                         views.TempBaseFirewallStrategyView,
                         basename='base-firewall',
                         parents_query_lookups=['template'])
template_router.register('modbus',
                         views.TempModbusStrategyView,
                         basename='modbus',
                         parents_query_lookups=['template'])
template_router.register('s7',
                         views.TempS7StrategyView,
                         basename='s7',
                         parents_query_lookups=['template'])

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^client/log', views.FirewallLogUploadView.as_view(), name='firewall-log-upload'),
    url(r'^client/whitelist/learn', views.LearnedWhiteListUploadView.as_view(), name='firewall-white-list-upload'),
    url(r'^client/ipmac/learn', views.IPMACUploadView.as_view(), name='firewall-ip-mac-upload')
]
