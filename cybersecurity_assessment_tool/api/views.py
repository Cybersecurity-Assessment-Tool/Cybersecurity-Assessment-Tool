from urllib import request
import uuid
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from api.utils.email_factory import send_email_by_type
import time
from api.forms import PublicRegistrationForm
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Invitation, Organization, User, Report, Risk
from .serializers import OrganizationSerializer, UserSerializer, ReportSerializer, RiskSerializer
from django.contrib.auth import get_user_model
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse
import json
from django.urls import reverse

User = get_user_model()


# Simple session-based OTP storage (use Redis/Cache in production)
@require_POST
@ensure_csrf_cookie
def otp_verify_view(request):
    """Verify OTP code"""
    print("="*50)
    print("otp_verify_view called!")
    
    try:
        # Handle both JSON and form data
        if request.content_type and 'application/json' in request.content_type:
            data = json.loads(request.body)
        else:
            data = request.POST
        
        print(f"Verify data: {data}")
        
        # Handle both formats (otp_input from your form, or otp_code from other implementations)
        otp_input = data.get('otp_input') or data.get('otp_code')
        email = data.get('email')
        purpose = data.get('purpose', 'registration')
        
        print(f"Verifying - Email: {email}, OTP: {otp_input}, Purpose: {purpose}")
        
        if not all([otp_input, email]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        stored_otp = request.session.get('otp_code')
        stored_email = request.session.get('otp_email')
        stored_purpose = request.session.get('otp_purpose')
        otp_created = request.session.get('otp_created')
        
        print(f"Stored - Email: {stored_email}, OTP: {stored_otp}, Purpose: {stored_purpose}")
        
        # Check if OTP expired (5 minutes)
        if not stored_otp or not otp_created:
            return JsonResponse({'error': 'No OTP found. Please request a new one.'}, status=400)
        
        if time.time() - otp_created > 300:
            # Clear expired OTP
            request.session.pop('otp_code', None)
            request.session.pop('otp_created', None)
            return JsonResponse({'error': 'OTP expired. Please request a new one.'}, status=400)
        
        if (stored_otp == otp_input and 
            stored_email == email and 
            stored_purpose == purpose):
            
            # Mark as verified
            request.session[f'{purpose}_verified_{email}'] = True
            request.session['verified_email'] = email
            
            # Clear OTP from session
            request.session.pop('otp_code', None)
            request.session.pop('otp_created', None)
            
            print("OTP verified successfully!")
            print("="*50)
            
            return JsonResponse({'success': True, 'message': 'OTP verified successfully'})
        else:
            print("OTP verification failed - invalid code")
            print("="*50)
            return JsonResponse({'error': 'Invalid verification code.'}, status=400)
            
    except Exception as e:
        print(f"ERROR in otp_verify_view: {str(e)}")
        import traceback
        traceback.print_exc()
        print("="*50)
        return JsonResponse({'error': str(e)}, status=500)

@require_POST
@ensure_csrf_cookie
def send_otp_view(request):
    """Send OTP to user using email_factory"""
    print("="*50)
    print("send_otp_view called!")
    print(f"Request method: {request.method}")
    print(f"Content-Type: {request.content_type}")
    print(f"Request POST data: {request.POST}")
    print(f"Request body: {request.body}")
    
    try:
        # Handle both JSON and form data
        if request.content_type and 'application/json' in request.content_type:
            # JSON data
            try:
                data = json.loads(request.body)
                print("Parsed JSON data:", data)
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                return JsonResponse({'error': 'Invalid JSON'}, status=400)
        else:
            # Form data
            data = request.POST
            print("Form data:", data)
        
        recipient = data.get('email')
        purpose = data.get('purpose', 'registration')
        
        print(f"Recipient: {recipient}, Purpose: {purpose}")
        
        if not recipient:
            return JsonResponse({'error': 'Email is required'}, status=400)
        
        # Send OTP using your factory
        try:
            context = send_email_by_type('otp', recipient)
            otp = context['otp']
            print(f"Generated OTP for {recipient}: {otp}")
        except Exception as e:
            print(f"Error in send_email_by_type: {e}")
            import traceback
            traceback.print_exc()
            return JsonResponse({'error': 'Failed to send email'}, status=500)
        
        # Store in session
        request.session['otp_code'] = otp
        request.session['otp_email'] = recipient
        request.session['otp_purpose'] = purpose
        request.session['otp_created'] = time.time()
        
        print("OTP stored in session successfully")
        print("="*50)
        
        return JsonResponse({'success': True, 'message': 'OTP sent successfully'})
        
    except Exception as e:
        print(f"ERROR in send_otp_view: {str(e)}")
        import traceback
        traceback.print_exc()
        print("="*50)
        return JsonResponse({'error': str(e)}, status=500)

def send_invite_mail(request, recipient_email):
    token = str(uuid.uuid4())  # Generate a unique token for the invite link
    
    invitation = Invitation.objects.create(
            sender=request.user,
            recipient_email=recipient_email,
            token=token,
            recipient_role=request.get('recipient_role', 'observer'),  # Default to 'observer' if not provided
            status='sent',
        )
    domain = request.get_host()
        
    send_email_by_type('invite', recipient_email, {
        "inviter_name": invitation.sender.username,
        "inviter_role": invitation.sender.group.help_text,
        "inviter_company": invitation.sender.organization.org_name,
        "company": invitation.sender.organization.org_name,
        "role": invitation.recipient_role,
        "invite_link": f"http://{domain}/invite/{token}/",
    })
        
def register_user_invite(request, invitation):
    if request.method == 'POST':
        user = form.save(commit=False)
        user.is_active = False  # ← Pending OTP verification
        user.object.create(
            id = request.session.get('pending_user_id'),
            username = request.session['registration_data']['username'],
        )
            
        send_email_by_type('registration', invitation.recipient_email, {
            "username": user.username
        })
        send_email_by_type('request', invitation.sender.email, {
            "requester_name": user.username,
            "requester_email": user.email,
            "company": invitation.sender.organization.org_name,
            "role": invitation.recipient_role
        })

# Takes care of public registration for Org Admins and company databases         
def public_registration(request):
    
    #Automatic invite token generated
    token = str(uuid.uuid4())
    if request.method == 'POST':
        form = PublicRegistrationForm(request.POST)
        
        # Debug Info
        # print("POST data:", request.POST)           # What was submitted
        # print("Form errors:", form.errors)          # What failed validation
        # print("Form is valid:", form.is_valid())    # Should be True
        
        #Checking all requirements for public registration form
        if form.is_valid():
            user = form.save()
            
            # Debug Info
            print(f"=== USER CREATED ===")
            print(f"Username: {user.username}")
            print(f"Email: {user.email}")
            print(f"Active: {user.is_active}")
            print(f"Organization: {user.organization}")
            print(f"User ID: {user.id}")

            # Our information email that receives the registration request and "sends" the invite
            # system_user = User.objects.get(username="Cybersecurity Assessment Tool")
            # system_user.email = "cyberassessmenttool@gmail.com"
            system_user = User.objects.get(username="Frontend Integration Testing")
            system_user.email = "ibinstock1@yahoo.com"

            # Creates invitation for the new user with status "sent" (pending approval) and default role of "Org Admin" 
            Invitation.objects.create(
                sender=system_user,
                recipient_email=user.email,
                token=str(uuid.uuid4()),
                recipient_role="Org Admin",
                status="sent",
                organization=user.organization
            )
            
            # print("After Save")

            # Sends email to the new user confirming their registration request
            send_email_by_type('registration', user.email, {
                "username": user.username
            })
            
            # Get the domain for absolute URLs
            approve_path = reverse('approve_registration', args=[user.id])
            reject_path = reverse('reject_registration', args=[user.id])

            domain = request.get_host()
            protocol = 'https' if request.is_secure() else 'http'
            approve_url = f"{protocol}://{domain}{approve_path}"
            reject_url = f"{protocol}://{domain}{reject_path}"

            print(f"Generated approve URL: {approve_url}")
            print(f"Generated reject URL: {reject_url}")

            # Sends email to the system admin
            send_email_by_type('request', system_user.email, {
                'requester_name': f"{user.first_name} {user.last_name}",
                "requester_email": user.email,
                "company": user.organization.org_name,
                "role": "Org Admin",
                "approve_url": approve_url,
                "reject_url": reject_url
            })
            
            messages.success(request, 'Registration successful. Please wait for admin approval.')
            return redirect('accounts:waiting')
        else:
            print(form.errors)
    else:
        form = PublicRegistrationForm()
    
    return render(request, 'registration/public_registration.html', {'form': form})

@staff_member_required
def approve_registration(request, user_id):  # user_id will be an integer
    """Approve a user's registration request by ID"""
    print(f"Approval requested for user ID: {user_id}")
    
    try:
        # Use 'id' field (Django's default auto-incrementing primary key)
        user = User.objects.get(id=user_id, is_active=False)
        print(f"Found user: {user.username}, email: {user.email}")
    except User.DoesNotExist:
        messages.error(request, f"No pending user found with ID {user_id}")
        return redirect('admin:api_user_changelist')
    
    # Activate the user
    user.is_active = True
    user.save()
    
    # Send approval email
    try:
        send_email_by_type('approval', user.email, {
            "username": user.username
        })
    except Exception as e:
        print(f"Error sending approval email: {e}")
    
    messages.success(request, f"User {user.username} has been approved.")
    return redirect('admin:api_user_changelist')


@staff_member_required
def reject_registration(request, user_id):
    """Reject a user's registration request by ID"""
    print(f"Rejection requested for user ID: {user_id}")
    
    try:
        user = User.objects.get(id=user_id, is_active=False)
        username = user.username
        user_email = user.email
        
        # Send rejection email
        send_email_by_type('rejection', user_email, {
            "username": username,
            "company": user.organization.org_name if user.organization else "Your Company",
            "role": "Org Admin"
        })
        
        # Delete the user
        user.delete()
        
        messages.success(request, f"User {username} has been rejected and removed.")
        
    except User.DoesNotExist:
        messages.error(request, f"No pending user found with ID {user_id}")
    
    return redirect('admin:api_user_changelist')

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

from django.contrib.auth.decorators import login_required
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
