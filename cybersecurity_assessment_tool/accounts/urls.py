# accounts/urls.py
from django.urls import path
import api.views as views
from rest_framework.routers import DefaultRouter

from .views import SignUpView


urlpatterns = [
    #path("signup/", SignUpView.as_view(), name="signup"),
    path('register/', SignUpView.as_view(), name='registration'),
    path('otp/verify/', views.otp_verify_view, name='otp_verify'),
    path('otp/send/', views.send_otp_view, name='resend_otp'),
    path('public-signup/', views.public_registration, name='public_registration'),
]
