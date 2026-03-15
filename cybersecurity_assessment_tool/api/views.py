from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Organization, User, Report, Risk
from .serializers import OrganizationSerializer, UserSerializer, ReportSerializer, RiskSerializer
from django.contrib.auth import get_user_model

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
        # Only show reports belonging to the user's organization
        return Report.objects.filter(organization=self.request.user.organization).order_by('-started')
        
    # automatically set the user_created and organization fields on creation
    def perform_create(self, serializer):
        serializer.save(user_created=self.request.user, organization=self.request.user.organization)


class RiskViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing Risk instances.
    """
    queryset = Risk.objects.all()
    serializer_class = RiskSerializer
    permission_classes = [IsAuthenticated]
    
    # will restrict this further (only show risks related to reports the user can access)
    # for now, it shows all risks



# TEST below
from django.shortcuts import get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from .services.report_manager import generate_network_ai_report
from django_q.tasks import async_task
from django_q.models import Task
from django.contrib.auth.decorators import login_required

def home(request):
    """Display home page"""
    context = {
        'page_title': 'LogoSoon',
        'description': 'Cybersecurity assessment tool',
    }
    return render(request, 'home.html', context)

@login_required
@require_POST
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

import json
from django.db.models import Count, Q
from django.core.paginator import Paginator
from django.contrib import messages

@login_required
def dashboard(request):
    """Display dashboard page with data from most recent scan only"""
    user = request.user
    organization = user.organization
    
    # Initialize empty data in case no reports exist
    vulnerabilities = []
    latest_report = None
    report_date = None
    
    if organization:
        # Get the most recent report for this organization
        latest_report = Report.objects.filter(
            organization=organization
        ).order_by('-completed').first()
        
        if latest_report:
            # Get all risks associated with this report
            vulnerabilities = list(
                Risk.objects.filter(
                    report_id=latest_report.report_id
                ).values('severity', 'risk_name', 'overview')
            )
            report_date = latest_report.completed
    
    context = {
        'vulnerabilities_json': json.dumps(vulnerabilities),
        'has_data': len(vulnerabilities) > 0,
        'latest_report': latest_report,
        'report_date': report_date,
        'total_vulns': len(vulnerabilities),
    }
    return render(request, 'dashboard.html', context)

@login_required
def risks_list(request):
    """Display all risks/vulnerabilities with filtering"""
    user = request.user
    organization = user.organization
    
    # Base queryset - if no organization, show empty results
    if organization:
        risks = Risk.objects.filter(organization=organization)
        has_organization = True
    else:
        risks = Risk.objects.none()
        has_organization = False
    
    severity_filter = request.GET.get('severity', '')
    if severity_filter:
        risks = risks.filter(severity=severity_filter)
    
    search_query = request.GET.get('search', '')
    if search_query:
        all_risks = list(risks)

        # Filtering in Python because the database has encrypted data which can't be filtered
        matching_risk_ids = []
        for risk in all_risks:
            if (search_query.lower() in risk.risk_name.lower() or 
                search_query.lower() in risk.overview.lower()):
                matching_risk_ids.append(risk.risk_id)

        risks = risks.filter(risk_id__in=matching_risk_ids)
    
    # Severity counts for filter badges - Calculate from BASE queryset (unfiltered)
    base_risks = Risk.objects.filter(organization=organization) if organization else Risk.objects.none()
    severity_counts = {
        'Critical': base_risks.filter(severity='Critical').count(),
        'High': base_risks.filter(severity='High').count(),
        'Medium': base_risks.filter(severity='Medium').count(),
        'Low': base_risks.filter(severity='Low').count(),
        'Info': base_risks.filter(severity='Info').count(),
    }
    
    # Pagination - order by report completion date
    if risks.exists():
        risks = risks.order_by('-report__completed')
    
    paginator = Paginator(risks, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    # For the severity breakdown chart
    risks_json = '[]'
    if base_risks.exists():
        risks_data = list(base_risks.values('risk_id', 'severity', 'risk_name')[:100])
        
        # Convert UUID objects to strings
        for item in risks_data:
            if 'risk_id' in item and item['risk_id']:
                item['risk_id'] = str(item['risk_id'])
        
        # Serialize to JSON
        risks_json = json.dumps(risks_data)
    
    context = {
        'page_obj': page_obj,
        'severity_counts': severity_counts,
        'current_severity': severity_filter,
        'severity_filter': severity_filter,
        'search_query': search_query,
        'total_risks': base_risks.count(),
        'filtered_count': risks.count(),
        'has_organization': has_organization,
        'has_risks': base_risks.exists(),
        # 'risks_json': risks_json,
        # 'has_data': risks.exists(),
    }
    return render(request, 'api/risks.html', context)

@login_required
def risk_detail(request, risk_id):
    """Display detailed view of a single risk"""
    try:
        risk = Risk.objects.get(risk_id=risk_id)
    except Risk.DoesNotExist:
        messages.error(request, "Risk not found.")
        return redirect('risks')
    
    # Permission check
    try:
        user_org = request.user.organization
        if not user_org or risk.organization != user_org:
            messages.error(request, "You don't have permission to view this risk.")
            return redirect('risks')    
    except:
        messages.error(request, "Unable to verify permissions.")
        return redirect('risks')
    
    # Parse affected elements back to list for display
    affected_elements_list = []
    if risk.affected_elements:
        affected_elements_list = [elem.strip() for elem in risk.affected_elements.split(',') if elem.strip()]
    
    context = {
        'risk': risk,
        'affected_elements_list': affected_elements_list,
    }
    return render(request, 'api/risk_detail.html', context)

@login_required
def report_list(request):
    """Display all generated reports"""
    user = request.user
    organization = user.organization
    
    # Get reports
    if organization:
        reports = Report.objects.filter(organization=organization).order_by('-completed')
        has_organization = True
    else:
        reports = Report.objects.none()
        has_organization = False
        # messages.info(request, "No organization associated with your account. Please contact an administrator.")
    
    # Add risk counts to each report
    report_list = []
    for report in reports:
        report_risks = Risk.objects.filter(report_id=report.report_id)

        # Get severity counts
        critical_count = report_risks.filter(severity='Critical').count()
        high_count = report_risks.filter(severity='High').count()
        medium_count = report_risks.filter(severity='Medium').count()
        low_count = report_risks.filter(severity='Low').count()
        info_count = report_risks.filter(severity='Info').count()

        print(f"{report.report_name} crit: {critical_count}")
        
        # Create a safe report object with calculated fields
        report_data = {
            'id': report.report_id,
            'report_id': report.report_id,
            'report_name': report.report_name,
            'completed': report.completed,
            'user_created': report.user_created,
            'risk_count': report_risks.count(),
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'info_count': info_count,
        }
        report_list.append(report_data)
    
    # Pagination
    paginator = Paginator(report_list, 10)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'total_reports': len(report_list),
        'has_data': len(report_list) > 0,
        'has_organization': has_organization,
        'user': user,
        'organization': organization,
    }
    return render(request, 'api/report_list.html', context)

@login_required
def report_detail(request, report_id):
    """Display a specific report with its risks"""
    try:
        report = Report.objects.get(report_id=report_id)
    except Report.DoesNotExist:
        messages.error(request, "Report not found.")
        return redirect('report_list')
    
    # Permission check
    try:
        user_org = request.user.organization
        if not user_org or report.organization != user_org:
            messages.error(request, "You don't have permission to view this report.")
            return redirect('report_list')
    except:
        messages.error(request, "Unable to verify permissions.")
        return redirect('report_list')
    
    # Get all risks for this report
    risks = Risk.objects.filter(report_id=report.report_id)
    
    # Group by severity for display
    severity_groups = {
        'Critical': risks.filter(severity='Critical') if risks.exists() else [],
        'High': risks.filter(severity='High') if risks.exists() else [],
        'Medium': risks.filter(severity='Medium') if risks.exists() else [],
        'Low': risks.filter(severity='Low') if risks.exists() else [],
        'Info': risks.filter(severity='Info') if risks.exists() else [],
    }
    
    context = {
        'report': report,
        'severity_groups': severity_groups,
        'total_risks': risks.count(),
        'has_risks': risks.exists(),
    }
    return render(request, 'api/report_detail.html', context)

@login_required
def scan(request):
    """Display scan page"""
    return render(request, 'scan.html')

@login_required
def settings(request):
    """Display settings page"""
    return render(request, 'settings.html')

@login_required
def profile(request):
    """Display profile page"""
    return render(request, 'profile.html')