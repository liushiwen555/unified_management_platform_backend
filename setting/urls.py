from django.conf.urls import url

from setting import views

urlpatterns = [
    url(r'^product-info/$', views.ProductInfoView.as_view(), name='product-info'),
    url(r'^ip/$', views.IPInfoView.as_view(), name='setting-ip'),
    url(r'^time/$', views.TimeInfoView.as_view(), name='setting-time'),
    url(r'^$', views.SettingView.as_view(), name='setting'),
    url(r'^ip-limit/$', views.IPLimitView.as_view(), name='ip-limit'),
    url(r'^reboot/$', views.RebootView.as_view(), name='setting-reboot'),
    url(r'^reset/$', views.ResetView.as_view(), name='setting-reset'),
    url(r'^disk/$', views.DiskView.as_view(), name='setting-disk'),
    url(r'^system-security/$', views.SystemSecurityView.as_view(),
        name='system-security'),
    url(r'^theme/$', views.ThemeSettingView.as_view(), name='setting-theme'),
    url(r'^location/$', views.LocationView.as_view(), name='setting-location'),
    url(r'^security-center-clean/$', views.SecurityCenterCleanView.as_view(),
        name='security-center-clean')
]
