# from django.urls import path, include
from django.conf.urls import url, include
from rest_framework.routers import SimpleRouter

from log import views

router = SimpleRouter()
router.register('unified-log', views.UnifiedForumLogView, basename='unified-log')
router.register('auditor-log', views.AuditLogView, basename='auditor-log')
router.register('firewall-log', views.FirewallSysEventView, basename='firewall-log')

# router.register('server-run-log', views.ServerRunLogView, basename='server-run-log')
# router.register('firewall-log', views.Firewall, basename='log')
# router.register(
#     'terminal-dev-installation-log',
#     views.TerminalInstallationLog,
#     basename='terminal-dev-installation-log')
# router.register('terminal-dev-run-log', views.TerminalRunLog, basename='terminal-dev-run-log')
# router.register(
#     'strategy-distribution-status-log',
#     views.StrategyDistributionStatusLogView,
#     basename='strategy-distribution-status-log')

router.register('event', views.EventLogView, basename='event')
router.register('all-alert', views.DeviceAllAlertView, basename='device-all-alert')
router.register('report-log', views.ReportLogView, basename='report-log')
router.register('security-event', views.SecurityEventView, basename='security-event')


urlpatterns = [
    url(r'report-log/(?P<pk>\d+)/download',
        views.ExportReportLogView.as_view(), name='download-report-log'),
    url(r'all-alert/resolve/all/', views.ResolveAllAlertView.as_view(),
        name='resolve-all-alert'),
    url(r'all-alert/resolve/batch/', views.BatchResolveAlertView.as_view(),
        name='batch-resolve-alert'),
    url(r'all-alert/resolve/(?P<pk>\d+)/', views.ResolveAlertView.as_view(),
        name='resolve-alert'),
    url(r'security-event/resolve/all/', views.ResolveAllSecurityView.as_view(),
        name='resolve-all-security'),
    url(r'security-event/resolve/batch/', views.BatchResolveSecurityView.as_view(),
        name='batch-resolve-security'),
    url(r'security-event/resolve/(?P<pk>\d+)/', views.ResolveSecurityView.as_view(),
        name='resolve-security'),
    url(r'auditor-protocol/', views.AuditorProtocolView.as_view(),
        name='auditor-protocol'),
    url(r'^', include(router.urls)),
]
