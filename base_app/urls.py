# from django.urls import path
from django.conf.urls import url, include
from rest_framework_extensions.routers import ExtendedSimpleRouter

from base_app import views

router = ExtendedSimpleRouter()
device_router = router.register('device', views.DeviceBaseView, basename='device-manage')

urlpatterns = [
    url(r'^heartbeat$', views.HeartbeatView.as_view(), name='heartbeat'),
    url(r'^device/download/batch/', views.ExportDeviceView.as_view(), name='export-device'),
    url(r'^device/download/all/', views.ExportAllDeviceView.as_view(), name='export-all-device'),
    url(r'^device/export_template$', views.ExportDeviceTemplateView.as_view(),
        name='export-device-template'),
    url(r'^device/category_device_list', views.CategoryDeviceList.as_view(),
        name='category-device-list'),
    url(r'^device/batch/', views.DeviceBatchView.as_view(), name='device-batch'),
    url(r'^device/all/', views.DeviceAPIView.as_view(), name='device-api'),
    url(r'^', include(router.urls)),
]

urlpatterns += url(r'^device/dev_monitor_frequency$', views.DeviceMonitorFrequencyView.as_view(), name='dev_monitor_frequency'),
urlpatterns += url(r'^device/dev_monitor_threshold$', views.DeviceMonitorTresholdView.as_view(), name='dev_monitor_threshold'),