import json
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django_q.tasks import async_task
from django_q.models import Task

from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny

from .models import Organization, User, Report, Risk
from .serializers import OrganizationSerializer, UserSerializer, ReportSerializer, RiskSerializer
from .services.report_manager import generate_network_ai_report
from .services.chatbot_client import get_gemini_response

User = get_user_model()

class OrganizationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing Organization instances.
    Requires authentication to modify data.
    """
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [IsAuthenticated]


class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing User instances.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
   
    def get_permissions(self):
        if self.action == 'create':
            return [AllowAny()]
        return [IsAuthenticated()]


class ReportViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing Report instances.
    Automatically filters reports to the current user's organization (optional security measure).
    """
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]
    
    # restrict reports to the user's organization for basic data separation
    def get_queryset(self):
        user = self.request.user
        
        # Only show reports belonging to the user's organization
        if user.has_perm('api.can_view_any_report'):
            return Report.objects.all().order_by('-started')
        
        # Filter by organization
        if user.organization:
            return Report.objects.filter(organization=user.organization).order_by('-started')
        
        # Fallback
        return Report.objects.none()
        
    # automatically set the user_created and organization fields on creation
    def perform_create(self, serializer):
        serializer.save(user_created=self.request.user, organization=self.request.user.organization)


class RiskViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing Risk instances.
    """
    serializer_class = RiskSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        
        # Master override
        if user.has_perm('api.can_view_all_risk'):
            return Risk.objects.all()
        
        # Filter by organization
        if user.organization:
            return Risk.objects.filter(organization=user.organization)
        
        # Fallback
        return Risk.objects.none()

def home(request):
    """Display home page"""
    context = {
        'page_title': 'LogoSoon',
        'description': 'Cybersecurity assessment tool',
    }
    return render(request, 'home.html', context)

@login_required
@permission_required('api.view_risk', raise_exception=True)
def dashboard(request):
    """Display dashboard page"""
    user = request.user
    
    # Filter risks securely
    if user.has_perm('api.can_view_all_risk'):
        risks = Risk.objects.all()
    elif user.organization:
        risks = Risk.objects.filter(organization=user.organization)
    else:
        risks = Risk.objects.none()

    # Convert the filtered queryset into a list of dictionaries for JSON
    vulnerabilities = list(risks.values('severity', 'risk_name', 'overview'))
    
    return render(request, 'dashboard.html', {
        'vulnerabilities_json': json.dumps(vulnerabilities)
    })

@login_required
@permission_required('api.view_report', raise_exception=True)
def report_list(request):
    """Display list of reports"""
    user = request.user
    
    # Filter reports securely
    if user.has_perm('api.can_view_any_report'):
        reports = Report.objects.all()
    elif user.organization:
        reports = Report.objects.filter(organization=user.organization)
    else:
        reports = Report.objects.none()
    
    context = {
        'reports': reports,
        'total_count': reports.count()
    }
    return render(request, 'report_list.html', context)

# def report_detail(request, id):
#     """Display single report (not implemented yet)"""
#     report = get_object_or_404(Report, id=id)
    
#     context = {
#         'report': report
#     }
#     return render(request, 'reports/report_detail.html', context)

@login_required
def settings(request):
    """Display settings page"""
    return render(request, 'settings.html')

@login_required
def profile(request):
    """Display profile page"""
    return render(request, 'profile.html')

@login_required
@require_POST
@permission_required('api.can_generate_risk', raise_exception=True)
@permission_required('api.can_generate_report', raise_exception=True)
def trigger_report_generation(request):
    """
    Triggers the background network scan using Django Q2.
    """
    task_id = async_task(
        generate_network_ai_report,
        request.user.organization.external_ip,
        request.user.user_id,
        request.user.organization_id
    )
    
    return JsonResponse({
        'task_id': task_id,
        'status': 'Processing started...'
    }, status=202)

@login_required
def check_task_status(request, task_id):
    """
    Checks status using Django Q2's Task model.
    """
    # get_task returns the Task object if finished, or None if still running/queued
    task = Task.get_task(task_id)
    
    if task:
        # Task is finished (either succeeded or failed)
        if task.success:
            return JsonResponse({
                'state': 'SUCCESS',
                'task_id': task.id,
                'result': task.result
            })
        else:
            return JsonResponse({
                'state': 'FAILURE',
                'task_id': task.id,
                'error': str(task.result) # Q2 stores the error traceback in 'result' on failure
            })
    else:
        # Task is not in the database yet, meaning it is still running
        return JsonResponse({
            'state': 'PENDING',
            'task_id': task_id,
            'step': 'Processing in background...'
        })

@login_required
@require_POST
@permission_required('api.view_report', raise_exception=True)
def chat_about_report(request, report_id):
    user_message = request.POST.get("prompt")
    
    # Fetch to verify it exists and check permissions
    report = get_object_or_404(Report, pk=report_id)
    
    if request.user.has_perm('api.can_view_any_report') or report.organization == request.user.organization:
        # Trigger the async task using the wrapper function
        task_id = async_task(
            'api.services.chatbot_client.generate_chat_reply_report', # Update 'api' if your app name is different
            report_id=report_id,
            user_message=user_message
        )
        # Return a 202 Accepted with the task_id
        return JsonResponse({'task_id': task_id, 'status': 'Processing started...'}, status=202)
    else:
        return JsonResponse({"error": "Unauthorized"}, status=403)
        
@login_required
@require_POST
@permission_required('api.view_risk', raise_exception=True)
def chat_about_risk(request, risk_id):
    user_message = request.POST.get("prompt")
    
    # Fetch to verify it exists and check permissions
    risk = get_object_or_404(Risk, pk=risk_id)
    
    if request.user.has_perm('api.can_view_any_risk') or risk.organization == request.user.organization:
        # Trigger the async task
        task_id = async_task(
            'api.services.chatbot_client.generate_chat_reply_risk', # Update 'api' if your app name is different
            risk_id=risk_id,
            user_message=user_message
        )
        # Return a 202 Accepted with the task_id
        return JsonResponse({'task_id': task_id, 'status': 'Processing started...'}, status=202)
    else:
        return JsonResponse({"error": "Unauthorized"}, status=403)