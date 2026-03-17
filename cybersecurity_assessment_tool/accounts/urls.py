from django.urls import path
from . import views
import api.views as api_views

app_name = 'accounts'

urlpatterns = [
    path("signup/", views.SignUpView.as_view(), name="signup"),
    path('signup/invite/<str:token>/', views.SignUpView.as_view(), name='invite_signup'),
    path('public-signup/', api_views.public_registration, name="public-signup"),
    path("user-detail/", views.UserDetailView.as_view(), name="user-detail"),
    path('settings/', views.settings, name='settings'),
    path('settings/upload-image/', views.upload_profile_image, name='upload_image'),
    path('settings/organization/', views.organization, name='organization'),
    path('invite/', api_views.process_invite_user_form, name = "invite_user"),
    path('invite/<str:token>/accept/', api_views.invite_accept, name='invite_accept'),
    path('admin/approve/<str:token>/', api_views.validate_invite, name='request_approved'),
]

# from .views import SignUpView


# urlpatterns = [
#     path("signup/", SignUpView.as_view(), name="signup"),
# ]
