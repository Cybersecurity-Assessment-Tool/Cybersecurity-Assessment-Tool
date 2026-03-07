from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import OrganizationViewSet, UserViewSet, ReportViewSet, RiskViewSet

router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet, basename='organization')
router.register(r'users', UserViewSet, basename='user')
router.register(r'reports', ReportViewSet, basename='report')
router.register(r'risks', RiskViewSet, basename='risk')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
]