from django.conf.urls import url, include
from rest_framework.routers import SimpleRouter

from unified_log import views

router = SimpleRouter()
router.register('rule', views.LogRuleView, basename='log-rule')
router.register('template', views.LogTemplateView, basename='log-template')

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^search_after/', views.LogSearchAfterView.as_view(),
        name='log-search-after'),
    url(r'^raw_search_after/', views.RawSearchAfterView.as_view(),
        name='log-raw-search-after'),
    url(r'^search', views.LogSearchView.as_view(), name='log-search'),
    url(r'^raw_search', views.RawLogSearchView.as_view(), name='log-raw-search'),
]
