from django.urls import path
from . import views

urlpatterns = [
    path("signup/", views.SignUpView.as_view(), name="signup"),
    # path("user-detail/", views.UserDetailView.as_view(), name="user-detail"),
    path('settings/', views.settings, name='settings'),
    path('settings/upload-image/', views.upload_profile_image, name='upload_image'),
    path('settings/organization/', views.organization, name='organization'),
]

# from .views import SignUpView


# urlpatterns = [
#     path("signup/", SignUpView.as_view(), name="signup"),
# ]
