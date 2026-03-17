from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import OrganizationViewSet, UserViewSet, ReportViewSet, RiskViewSet
import api.views as views

router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet)
router.register(r'users', UserViewSet)
router.register(r'reports', ReportViewSet, basename='report')
router.register(r'risks', RiskViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('otp/verify/', views.otp_verify_view, name='otp_verify'),
    path('otp/send/', views.send_otp_view, name='resend_otp'),
    path('public-signup/', views.public_registration, name='public_registration'),

    # Login URLs
    path('login/', views.login_view, name='login'),
    path('verify-login-otp/', views.verify_login_otp, name='verify_login_otp'),
    path('login-redirect/', views.questionnaire_redirect, name='login_redirect'),

    # Admin approval URLs
    path('admin/approve/<int:user_id>/', views.approve_registration, name='approve_registration'),
    path('admin/reject/<int:user_id>/', views.reject_registration, name='reject_registration'),
]