from django.urls import path
from api import views as api_views
from . import views
from rest_framework.routers import DefaultRouter
import api.views as api_views

app_name = 'accounts'

urlpatterns = [
    path("signup/", views.SignUpView.as_view(), name="signup"),
    path('settings/', views.settings_view, name='settings'),
    path('settings/upload-image/', views.upload_profile_image, name='upload_image'),
    path('settings/organization/', views.organization, name='organization'),

    # Public registration
    path('public-register/', views.public_register, name='public_register'),
    path('waiting/', views.waiting_page, name='waiting'),
    path('questionnaire/', views.questionnaire, name='questionnaire'),
    path('google-oauth-login/', api_views.google_oauth_login, name='google_oauth_login'),
    path('google-oauth-signup/', api_views.google_oauth_signup, name='google_oauth_signup'),
    
    # OTP endpoints
    path('send-otp/', views.send_otp, name='send_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    
    # Team management
    path('team/members/', views.team_members, name='team_members'),
    path('team/remove/', views.remove_member, name='remove_member'),
    path('team/invites/', views.pending_invites, name='pending_invites'),
    path('team/invite/', views.send_invitation, name='send_invitation'),
    path('team/invite/resend/', views.resend_invitation, name='resend_invitation'),
    path('team/invite/cancel/', views.cancel_invitation, name='cancel_invitation'),
    path('invite/<uuid:token>/', views.accept_invitation, name='accept_invitation'),
    
    # Registration status
    path('check-status/', api_views.check_registration_status, name='check_registration_status'),

    # Password Change URLs
    path('password_change/', views.CustomPasswordChangeView.as_view(), name='password_change'),
    path('password_change/done/', views.CustomPasswordChangeDoneView.as_view(), name='password_change_done'),

    # Password Reset URLs
    path('password_reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
]
