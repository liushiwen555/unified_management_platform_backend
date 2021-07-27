from django.conf.urls import url, include
from django.urls import path

from statistic import views

main_view = [
    url(r'assets_center/', views.AssetsCenterView.as_view(),
        name='assets-center'),
    url(r'monitor_center/', views.MonitorCenterView.as_view(),
        name='monitor-center'),
    url(r'log_center/', views.LogCenterView.as_view(), name='log-center'),
    url(r'alert_process/', views.AlertProcessView.as_view(),
        name='alert-process'),
    url(r'alert_threat/', views.AlertThreatView.as_view(), name='alert-threat'),
    url(r'network_center/', views.NetworkTrafficView.as_view(),
        name='network-center'),
    url(r'$', views.MainViewSet.as_view(), name='main-view'),
]

performance_view = [
    url(r'snmp_data/', views.SNMPDataView.as_view(), name='snmp-data'),
]

running_view = [
    url(r'system_status/', views.SystemRunningView.as_view(),
        name='system-running'),
    url(r'system_info/', views.SystemInfoView.as_view(), name='system-info'),
    url(r'user_info/', views.UserDistributionView.as_view(), name='user-info'),
    url(r'unresolved_alert/', views.UnResolvedAlertView.as_view(),
        name='unresolved-alert'),
]

log_view = [
    url(r'total/', views.LogStatisticView.as_view(), name='log-total'),
    url(r'day_trend/', views.LogStatisticDayView.as_view(),
        name='log-day-trend'),
    url(r'hour_trend/', views.LogStatisticHourView.as_view(),
        name='log-hour-trend'),
    url(r'collect_top_five/', views.LogDeviceTopFiveView.as_view(),
        name='log-device-top-five'),
    url(r'dst_ip_top_five/', views.LogDstIPTopFiveView.as_view(),
        name='log-dst-ip-top-five'),
    url(r'category_distribution/', views.CategoryDistributionViews.as_view(),
        name='log-category-distribution'),
    url(r'port_distribution/', views.PortDistributionViews.as_view(),
        name='log-port-distribution'),
]

assets_view = [
    url(r'category_distribution/', views.DeviceDistributionView.as_view(),
        name='category-distribution'),
    url(r'total/', views.DeviceTotalView.as_view(), name='device-total'),
    url(r'risk_top_five/', views.RiskDeviceTopFiveView.as_view(),
        name='risk-device-top-5'),
    url(r'ip_distribution/', views.AssetsIPView.as_view(),
        name='ip-distribution'),
    url(r'external_ip_top_five/', views.ExternalIPTopFiveView.as_view(),
        name='external-ip-top-5'),
]

network_view = [
    url(r'protocol_traffics/', views.ProtocolTrafficView.as_view(),
        name='protocol-traffics'),
    url(r'protocol_distribution/', views.ProtocolDistributionView.as_view(),
        name='protocol-distribution'),
    url(r'device_traffics/', views.DeviceTrafficView.as_view(),
        name='device-traffics'),
    url(r'port_top_five/', views.PortTopFiveView.as_view(),
        name='port-top-five'),
    url(r'ip_top_five/', views.IPTopFiveView.as_view(),
        name='ip-top-five'),
]

security_view = [
    url(r'ip_map/', views.IPMapView.as_view(), name='ip-map'),
    url(r'risk_country_top_five/', views.RiskCountryTopFiveView.as_view(),
        name='country-top-five'),
    url(r'attack_statistic/', views.AttackStatisticView.as_view(),
        name='attack-statistic'),
    url(r'device_alert_distribution/',
        views.DeviceAlertDistributionView.as_view(),
        name='device-alert-distribution'),
    url(r'alert_realtime/', views.DeviceAlertRealtimeView.as_view(),
        name='alert-realtime'),
    url(r'alert_trend/', views.AlertTrendView.as_view(), name='alert-trend'),
]

abnormal_view = [
    url(r'alert_week_trend/', views.AlertWeekTrendView.as_view(),
        name='alert-week-trend'),
    url(r'locked_user/', views.LockedUserView.as_view(), name='locked-user'),
    url(r'abnormal_login/', views.AbnormalLoginView.as_view(),
        name='abnormal-login'),
    url(r'abnormal_behavior/', views.AbnormalBehaviorView.as_view(),
        name='abnormal-behavior'),
]

attack_view = [
    url(r'attack_ip_top_five/', views.AttackIPRankView.as_view(),
        name='attack-ip-top-five'),
    url(r'alert_realtime/', views.AlertRealtimeView.as_view(),
        name='alert-realtime'),
    url(r'attack_location_top_five/', views.AttackLocationView.as_view(),
        name='attack-location'),
    url(r'alert_ip_top_five/', views.AlertIPRankView.as_view(),
        name='alert-ip-top-five'),
]

urlpatterns = [
    url(r'^main/', include(main_view)),
    url(r'^performance/', include(performance_view)),
    url(r'^running/', include(running_view)),
    url(r'^log/', include(log_view)),
    url(r'^assets/', include(assets_view)),
    url(r'^network/', include(network_view)),
    url(r'^security/', include(security_view)),
    url(r'^abnormal/', include(abnormal_view)),
    url(r'^attack/', include(attack_view)),
    path('test/', views.room, name='room'),
]
