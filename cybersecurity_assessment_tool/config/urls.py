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
    path("accounts/", include("accounts.urls")),
    path("accounts/", include("django.contrib.auth.urls")),
    
    # Test segment 2
    path('', views.home, name='home'),  # Home page
    path('dashboard/', views.dashboard, name='dashboard'),  # /dashboard/
    path('reports/', views.report_list, name='report_list'),  # /reports/
    # path('reports/<int:id>/', views.report_detail, name='report_detail'),  # /reports/1/
    path('settings/', views.settings, name='settings'),  # /settings/
    path('profile/', views.profile, name='profile'),  # /profile/

    # path('questionnaire/', views.home, name='questionnaire'),  # /questionnaire/ (not implemented yet)
]

if not settings.TESTING:
    from debug_toolbar.toolbar import debug_toolbar_urls

    urlpatterns = [
        *urlpatterns,
        path('api/v1/', include('api.urls')), # to see the backend engine (DEV ONLY)
    ] + debug_toolbar_urls()
