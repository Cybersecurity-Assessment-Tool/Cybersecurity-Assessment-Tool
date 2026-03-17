from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import OrganizationViewSet, UserViewSet, ReportViewSet, RiskViewSet, send_otp_view, public_registration, process_invite_user_form
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
    #path('invite/', views.process_invite_user_form, name="invite_user"),
]
