from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import OrganizationViewSet, UserViewSet, ReportViewSet, RiskViewSet
import api.views as views
from .views_scan import (
    generate_scan_token,
    submit_scan_results,
    scan_status,
    list_scans,
    start_server_scan,
)

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
    # path('public-signup/', views.public_registration, name='public_registration'),

    # Login / signup OAuth URLs
    # path('login/', views.login_view, name='login'),
    path('google-oauth/start/', views.google_oauth_start, name='google_oauth_start'),
    path('google-oauth/callback/', views.google_oauth_callback, name='google_oauth_callback'),
    path('microsoft-oauth/start/', views.microsoft_oauth_start, name='microsoft_oauth_start'),
    path('microsoft-oauth/callback/', views.microsoft_oauth_callback, name='microsoft_oauth_callback'),
    path('google-oauth-login/', views.google_oauth_login, name='google_oauth_login'),
    path('google-oauth-signup/', views.google_oauth_signup, name='google_oauth_signup'),
    path('verify-login-otp/', views.verify_login_otp, name='verify_login_otp'),
    path('resend-login-otp/', views.resend_login_otp, name='resend_login_otp'),
    path('login-redirect/', views.questionnaire_redirect, name='login_redirect'),

    # Admin approval URLs
    path('admin/approve/<int:user_id>/', views.approve_registration, name='approve_registration'),
    path('admin/reject/<int:user_id>/', views.reject_registration, name='reject_registration'),

    # Resolving risks
    path('api/risks/<uuid:risk_id>/resolve/', views.resolve_risk, name='resolve_risk'),

    # Scan URLs
    path('scan/token/', generate_scan_token, name='scan_token'),
    path('scan/submit/', submit_scan_results, name='scan_submit'),
    path('scan/status/<uuid:scan_id>/', scan_status, name='scan_status'),
    path('scan/list/', list_scans, name='scan_list'),
    path('scan/download/', views.download_scanner_exe, name='scan_download_exe'),
    path('scan/start/', start_server_scan, name='scan_server_start'),
]
