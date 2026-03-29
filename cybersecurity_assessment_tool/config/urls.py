"""
URL configuration for api project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import path, include, path

# Test segment 1
from api import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    path('accounts/login/', views.login_view, name='login'),
    path("accounts/", include("accounts.urls")),
    path("accounts/", include("django.contrib.auth.urls")),
    
    # Test segment 2
    path('', views.home, name='home'),  # Home page
    path('dashboard/', views.dashboard, name='dashboard'),  # /dashboard/
    path('reports/', views.report_list, name='report_list'),  # /reports/
    path('reports/<uuid:report_id>/', views.report_detail, name='report_detail'),  # /reports/1/
    path('risks/', views.risks_list, name='risks_list'),  # /risks/
    path('risks/<uuid:risk_id>/', views.risk_detail, name='risk_detail'),  # /risk/1/
    path('scan/', views.scan, name='scan'),  # /scan/

    path('tasks/<str:task_id>/', views.check_task_status, name='check_task_status'),

    ## DEBUG
    path('test-email/', views.test_sendgrid, name='test_email'),
]

## cat hate BANAN

# Add debug toolbar only if it's installed
if settings.DEBUG and 'debug_toolbar' in settings.INSTALLED_APPS:
    try:
        from debug_toolbar.toolbar import debug_toolbar_urls
        urlpatterns += debug_toolbar_urls()
    except ImportError:
        pass  # debug_toolbar not installed, ignore