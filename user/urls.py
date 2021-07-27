# from django.urls import path, include
from django.conf.urls import url, include
from rest_framework.routers import SimpleRouter

from user import views

router = SimpleRouter()
router.register('', views.UserView, basename='user-view')

urlpatterns = [
    url(r'^login/$', views.LoginView.as_view(), name='user-login'),
    url(r'^logout/$', views.LogoutView.as_view(), name='user-logout'),
    url(r'^change-password/$', views.ChangePasswordView.as_view(), name='change-password'),
    url(r'^reset-password/(?P<pk>[0-9]+)/$', views.ResetPasswordView.as_view(), name='reset-password'),
    url(r'^', include(router.urls)),
]
