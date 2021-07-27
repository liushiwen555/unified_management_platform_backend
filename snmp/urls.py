from django.conf.urls import include, url

from rest_framework.routers import SimpleRouter

from snmp import views

router = SimpleRouter()
router.register(r'rule', views.SNMPRuleView)
router.register(r'template', views.SNMPTemplateView)

urlpatterns = [
    url(r'^', include(router.urls))
]
