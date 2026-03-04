from django.urls import path

# Test
from .views import SignUpView, UserDetailView

urlpatterns = [
    path("signup/", SignUpView.as_view(), name="signup"),
    path("user-detail/", UserDetailView.as_view(), name="user-detail"),
]

# from .views import SignUpView


# urlpatterns = [
#     path("signup/", SignUpView.as_view(), name="signup"),
# ]
