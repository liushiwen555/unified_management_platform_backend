from django.conf.urls import url

from home import views

urlpatterns = [
    # url(r'^sys-usage/$', views.SysUsageView.as_view(), name='sys-usage'),
    # url(r'^event-stat/$', views.EventStatView.as_view(), name='event-stat'),
    url(r'^notice/$', views.SecAlertView.as_view(), name='notice'),
    url(r'^device_static_info/$', views.DeviceStasticInfoView.as_view(), name='device_static'),
    url(r'^top_five_alert/$', views.TopFiveAlertInfo.as_view(), name='top_five_alert'),
    url(r'^newest_alert/$', views.NewAlertInfo.as_view(), name='newest_alert'),
    url(r'^alert_info/$', views.DeviceAlertInfo.as_view(), name='alert_info'),
    url(r'^alert_query/$', views.AlertQueryInfo.as_view(), name='alert_query'),
]
