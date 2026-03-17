from django.urls import path
from api import views as api_views
from . import views
from rest_framework.routers import DefaultRouter

app_name = 'accounts'

urlpatterns = [
    path("signup/", views.SignUpView.as_view(), name="signup"),
    path("user-detail/", views.UserDetailView.as_view(), name="user-detail"), # remove later
    path('settings/', views.settings, name='settings'),
    path('settings/upload-image/', views.upload_profile_image, name='upload_image'),
    path('settings/organization/', views.organization, name='organization'),

    # Public registration
    path('public-register/', views.public_register, name='public_register'),
    path('waiting/', views.waiting_page, name='waiting'),
    path('questionnaire/', views.questionnaire, name='questionnaire'),
    
    # OTP endpoints
    path('send-otp/', views.send_otp, name='send_otp'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    
    # Team management
    path('team/members/', views.team_members, name='team_members'),
    path('team/invites/', views.pending_invites, name='pending_invites'),
    path('team/invite/', views.send_invitation, name='send_invitation'),
    path('team/invite/resend/', views.resend_invitation, name='resend_invitation'),
    path('team/invite/cancel/', views.cancel_invitation, name='cancel_invitation'),
    path('invite/<uuid:token>/', views.accept_invitation, name='accept_invitation'),
    
    # Registration status
    path('check-status/', api_views.check_registration_status, name='check_registration_status'),
]
