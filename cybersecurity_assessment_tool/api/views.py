import sys
from urllib import request
import uuid
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from api.utils.email_tasks import queue_email
import time
from django.utils import timezone
from accounts.forms import InvitationSignupForm, PublicRegistrationForm
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Invitation, Organization, User, Report, Risk, generate_email_hash
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from .serializers import OrganizationSerializer, UserSerializer, ReportSerializer, RiskSerializer
from django.contrib.auth import get_user_model
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import JsonResponse, HttpResponse
import json
from django.urls import reverse
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
import secrets
import os

User = get_user_model()

## Simple session-based OTP storage (use Redis/Cache in production)
# Checks expiration time and verifies otp
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

# Sends email with the help of email_factory.py
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
        
        # 1. Generate the OTP immediately in the view
        from api.utils.send_otp_mail import generate_otp
        otp = generate_otp()
        
        # 2. Queue the email in the background, passing the OTP as a context override
        try:
            queue_email('otp', recipient, {'otp': otp})
            
            print(f"Queued OTP email for {recipient}: {otp}")
        except Exception as e:
            print(f"Error queuing email: {e}")
            import traceback
            traceback.print_exc()
            return JsonResponse({'error': 'Failed to queue email'}, status=500)
        
        # 3. Store the OTP in the session
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
        
    queue_email('invite', recipient_email, {
        "inviter_name": invitation.sender.username,
        "inviter_role": invitation.sender.group.help_text,
        "inviter_company": invitation.sender.organization.org_name,
        "company": invitation.sender.organization.org_name,
        "role": invitation.recipient_role,
        "invite_link": f"http://{domain}/invite/{token}/",
    })
        
def register_user_invite(request, token):
    """Handle user registration via invitation link"""
    
    # 1. Safely check if the token exists at all (prevents hard crashes)
    try:
        invitation = Invitation.objects.get(token=token)
    except Invitation.DoesNotExist:
        messages.error(request, 'This invitation link is invalid.')
        return redirect('login')

    # 2. Check if it's already been used (friendly error instead of an invalid page)
    if invitation.status != 'sent':
        messages.error(request, 'This invitation has already been used or is no longer valid.')
        return redirect('login')

    # 3. Handle the form submission
    if request.method == 'POST':
        # Because the HTML email input is 'disabled', it doesn't send in the POST data.
        # We must manually copy the POST data and safely inject the email from the database.
        post_data = request.POST.copy()
        post_data['email'] = invitation.recipient_email
        
        form = InvitationSignupForm(post_data)
        
        if form.is_valid():
            # Create the user and activate immediately
            user = form.save(commit=False)
            user.email = invitation.recipient_email
            user.organization = invitation.organization
            user.is_active = True  # Automatically activate the user
            user.save()
            
            # Update invitation status
            invitation.recipient_user = user
            invitation.status = 'accepted'
            invitation.save()
            
            # Return the success context to trigger your 5-second redirect UI!
            context = {
                'success': True,
                'email': invitation.recipient_email,
                'organization': invitation.organization.org_name,
            }
            return render(request, 'registration/invite_signup.html', context)
    else:
        # GET request - initialize the form
        form = InvitationSignupForm(initial={'email': invitation.recipient_email})
    
    # Pass 'email' into the context so the {{ email }} template variable renders correctly
    context = {
        'form': form,
        'email': invitation.recipient_email, 
        'organization': invitation.organization.org_name,
    }
    return render(request, 'registration/invite_signup.html', context)

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

    # Update the invitation status to 'approved'
    invitation = Invitation.objects.filter(recipient_user=user).first()
    if invitation:
        invitation.status = 'approved'
        invitation.save()
    
    # Send approval email
    domain = request.get_host()
    try:
        queue_email('approval', user.email, {
            "username": user.username,
            "company": user.organization.org_name if user.organization else "Your Company",
            "login_url": f"http://{domain}/accounts/login/",
            "contact_email": settings.ADMIN_EMAIL_INBOX,
        })
    except Exception as e:
        print(f"Error queuing approval email: {e}")
    
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
        queue_email('rejection', user_email, {
            "username": username,
            "company": user.organization.org_name if user.organization else "Your Company",
            "role": "Org Admin",
            "contact_email": settings.ADMIN_EMAIL_INBOX,
        })

        # Delete the associated invitation first
        Invitation.objects.filter(recipient_user=user).delete()
        
        # Delete the user
        user.delete()
        
        messages.success(request, f"User {username} has been rejected and removed.")
        
    except User.DoesNotExist:
        messages.error(request, f"No pending user found with ID {user_id}")
    
    return redirect('admin:api_user_changelist')

def _get_login_context(form=None):
    """Shared context for rendering the login page."""
    google_client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '').strip()
    return {
        'form': form or AuthenticationForm(),
        'google_oauth_enabled': bool(google_client_id),
        'google_oauth_client_id': google_client_id,
    }


@require_POST
def google_oauth_login(request):
    """Log in an existing approved user with Google OAuth."""
    client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '').strip()
    is_test_request = getattr(settings, 'TESTING', False) or 'test' in sys.argv
    if not client_id and not is_test_request:
        return JsonResponse({
            'success': False,
            'error': 'Google OAuth is not configured for this environment.',
        }, status=503)

    try:
        data = json.loads(request.body) if request.body else request.POST
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid login payload.',
        }, status=400)

    credential = (data.get('credential') or data.get('id_token') or '').strip()
    if not credential:
        return JsonResponse({
            'success': False,
            'error': 'Missing Google credential.',
        }, status=400)

    try:
        token_payload = id_token.verify_oauth2_token(
            credential,
            google_requests.Request(),
            client_id or None,
        )
    except ValueError:
        return JsonResponse({
            'success': False,
            'error': 'Google sign-in could not be verified.',
        }, status=400)

    email = (token_payload.get('email') or '').strip().lower()
    if not email or not token_payload.get('email_verified'):
        return JsonResponse({
            'success': False,
            'error': 'Your Google email address is not verified.',
        }, status=403)

    user = User.objects.filter(email_hash=generate_email_hash(email)).first()
    if user is None:
        return JsonResponse({
            'success': False,
            'error': 'No approved account is linked to this Google email address.',
        }, status=403)

    if not user.is_active:
        return JsonResponse({
            'success': False,
            'error': 'Your account is pending approval. Please contact your administrator.',
        }, status=403)

    updated = False
    if token_payload.get('given_name') and not user.first_name:
        user.first_name = token_payload['given_name']
        updated = True
    if token_payload.get('family_name') and not user.last_name:
        user.last_name = token_payload['family_name']
        updated = True
    if updated:
        user.save()

    user.backend = 'django.contrib.auth.backends.ModelBackend'
    login(request, user)

    return JsonResponse({
        'success': True,
        'redirect_url': reverse('login_redirect'),
        'message': 'Signed in with Google successfully.',
    })


def login_view(request):
    """Custom login view that handles OTP verification"""
    if request.method == 'POST':
        # Handle AJAX requests properly
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            try:
                # Parse JSON data if sent as JSON
                if request.content_type == 'application/json':
                    data = json.loads(request.body)
                    username = data.get('username')
                    password = data.get('password')
                else:
                    # Handle form data
                    username = request.POST.get('username')
                    password = request.POST.get('password')
                
                # Authenticate user
                user = authenticate(request, username=username, password=password)
                
                if user is not None:
                    # Store user ID in session for OTP verification
                    request.session['pending_user_id'] = user.id
                    
                    # Generate otp
                    from api.utils.send_otp_mail import generate_otp
                    otp = generate_otp()
                    
                    # Send email
                    queue_email('otp', user.email, {'otp': otp})
                    
                    # Store OTP in session
                    request.session['login_otp'] = otp
                    request.session['login_otp_created'] = time.time()
                    request.session['login_email'] = user.email
                    
                    return JsonResponse({
                        'success': True,
                        'requires_otp': True,
                        'email': user.email,
                        'message': 'OTP sent to your email'
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'errors': {'__all__': ['Invalid username or password']}
                    }, status=400)
                    
            except Exception as e:
                print(f"Login error: {e}")
                return JsonResponse({
                    'success': False,
                    'errors': {'__all__': ['An error occurred. Please try again.']}
                }, status=500)
        else:
            # Regular form submission (fallback)
            form = AuthenticationForm(request, data=request.POST)
            if form.is_valid():
                username = form.cleaned_data.get('username')
                password = form.cleaned_data.get('password')
                user = authenticate(username=username, password=password)
                if user is not None:
                    from django.contrib.auth import login
                    login(request, user)
                    return redirect('dashboard')
            return render(request, 'registration/login.html', _get_login_context(form))
    
    # GET request - show login form
    form = AuthenticationForm()
    return render(request, 'registration/login.html', _get_login_context(form))

@require_POST
def verify_login_otp(request):
    """Verify OTP during login"""
    try:
        # Parse JSON data
        data = json.loads(request.body) if request.body else request.POST
        otp_input = data.get('otp_input')
        
        print(f"Verifying login OTP: {otp_input}")
        
        # Get stored OTP from session
        stored_otp = request.session.get('login_otp')
        stored_email = request.session.get('login_email')
        otp_created = request.session.get('login_otp_created')
        user_id = request.session.get('pending_user_id')
        
        print(f"Stored OTP: {stored_otp}, Email: {stored_email}, User ID: {user_id}")
        
        # Check if OTP expired (5 minutes)
        if not stored_otp or not otp_created or (time.time() - otp_created > 300):
            return JsonResponse({
                'success': False,
                'error': 'OTP expired. Please log in again.',
                'expired': True
            }, status=400)
        
        if stored_otp == otp_input:
            # OTP verified - log the user in
            try:
                from django.contrib.auth import login
                from django.urls import reverse  # Make sure this import is here
                
                user = User.objects.get(id=user_id)
                login(request, user)
                
                # Clear OTP session data
                request.session.pop('login_otp', None)
                request.session.pop('login_otp_created', None)
                request.session.pop('login_email', None)
                request.session.pop('pending_user_id', None)
                
                # Check if user needs to complete questionnaire
                needs_questionnaire = False
                
                # Debug info
                print(f"User {user.username} - Organization exists: {user.organization is not None}")
                
                if user.organization:
                    # Check if questionnaire is completed (this field is NOT encrypted)
                    print(f"Organization questionnaire_completed: {user.organization.questionnaire_completed}")
                    
                    # Check if this is the first user in the organization
                    # We need to get all users and check in Python due to encryption
                    all_users = User.objects.filter(organization=user.organization)
                    
                    # Find the first user by date_joined (this field is NOT encrypted)
                    first_user = None
                    earliest_date = None
                    
                    for u in all_users:
                        if earliest_date is None or u.date_joined < earliest_date:
                            earliest_date = u.date_joined
                            first_user = u
                    
                    is_first_user = (first_user and first_user.id == user.id)
                    print(f"Is first user? {is_first_user}")
                    
                    # Show questionnaire if:
                    # 1. This is the first user AND
                    # 2. Questionnaire not completed
                    if is_first_user and not user.organization.questionnaire_completed:
                        needs_questionnaire = True
                        print("✓ User needs questionnaire")
                    else:
                        print("✗ User does not need questionnaire")
                else:
                    print("User has no organization")
                
                # Generate proper redirect URLs using reverse
                if needs_questionnaire:
                    redirect_url = reverse('accounts:questionnaire')
                else:
                    redirect_url = reverse('dashboard')
                
                return JsonResponse({
                    'success': True,
                    'needs_questionnaire': needs_questionnaire,
                    'redirect_url': redirect_url,
                })
                
            except User.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'User not found'}, status=400)
        else:
            return JsonResponse({'success': False, 'error': 'Invalid verification code'}, status=400)
            
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid request format'}, status=400)
    except Exception as e:
        print(f"Error in verify_login_otp: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def questionnaire_redirect(request):
    user = request.user
    if user.organization and not user.organization.questionnaire_completed:
        all_users = User.objects.filter(organization=user.organization).order_by('date_joined')
        first_user = all_users.first()
        if first_user and first_user.id == user.id:
            return redirect('accounts:questionnaire')
    return redirect('dashboard')

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
from django_q.tasks import async_task
from django_q.models import Task

def check_registration_status(request):
    """AJAX endpoint to check if registration has been approved"""
    email = request.session.get('pending_email')
    
    if not email:
        return JsonResponse({'status': 'pending'})
    
    # Get all users and decrypt emails in Python
    users = User.objects.all()
    found_user = None
    
    for user in users:
        # Decrypt and compare (case-insensitive)
        if user.email.lower() == email.lower():
            found_user = user
            break
    
    if found_user:
        if found_user.is_active:
            # Clear session data
            request.session.pop('pending_company', None)
            request.session.pop('pending_email', None)
            request.session.pop('pending_submitted', None)
            return JsonResponse({'status': 'approved'})
        else:
            return JsonResponse({'status': 'pending'})
    else:
        return JsonResponse({'status': 'rejected'})

def waiting_page(request):
    """Waiting page shown after registration while awaiting approval"""
    email = request.session.get('pending_email')
    status = 'pending'
    company = request.session.get('pending_company', 'Your Organization')
    submitted = request.session.get('pending_submitted', timezone.now())

    if email:
        # Loop through all users to find matching email (due to encryption)
        users = User.objects.all()
        found_user = None
        for user in users:
            if user.email.lower() == email.lower():
                found_user = user
                break
        if found_user:
            if found_user.is_active:
                status = 'approved'
            else:
                status = 'pending'
        else:
            status = 'rejected'  # User deleted or not found

    context = {
        'company_name': company,
        'email': email,
        'submitted_at': submitted,
        'registration_status': status,
    }
    return render(request, 'registration/waiting.html', context)

def home(request):
    """Display home page"""
    context = {
        'page_title': 'RePortly',
        'description': 'Cybersecurity Assessment Tool',
        'contact_email': settings.ADMIN_EMAIL_INBOX
    }
    return render(request, 'home.html', context)

@require_POST
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
            # Iterate over the objects to force decryption
            risks = Risk.objects.filter(report=latest_report)
            
            for risk in risks:
                vulnerabilities.append({
                    'severity': risk.severity,
                    'risk_name': risk.risk_name,
                    'overview': risk.overview,
                })
            
            report_date = latest_report.completed if latest_report.completed else latest_report.started
    
    context = {
        'vulnerabilities_json': vulnerabilities,
        'has_data': len(vulnerabilities) > 0,
        'latest_report': latest_report,
        'report_date': report_date,
        'total_vulns': len(vulnerabilities),
    }
    return render(request, 'dashboard.html', context)

from django.db.models import Case, When, Value, IntegerField
@login_required
def risks_list(request):
    """Display all risks/vulnerabilities with filtering"""
    user = request.user
    organization = user.organization
    
    is_admin = False
    can_resolve_risk = False
    
    # Base queryset - filter out archived risks!
    if organization:
        risks = Risk.objects.filter(organization=organization, is_archived=False)
        has_organization = True
        
        # Determine if the user is the org admin (first user to join the org)
        first_user = User.objects.filter(organization=organization).order_by('date_joined').first()
        is_admin = (first_user == user)
        
        # Check if user has the specific django permission
        can_resolve_risk = user.has_perm('api.can_resolve_risk') 
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
    
    # Severity counts for filter badges - Calculate from BASE queryset (unfiltered, but unarchived)
    base_risks = Risk.objects.filter(organization=organization, is_archived=False) if organization else Risk.objects.none()
    severity_counts = {
        'Critical': base_risks.filter(severity='Critical').count(),
        'High': base_risks.filter(severity='High').count(),
        'Medium': base_risks.filter(severity='Medium').count(),
        'Low': base_risks.filter(severity='Low').count(),
        'Info': base_risks.filter(severity='Info').count(),
    }
    
    # Pagination - order by Severity first, then by report completion date
    if risks.exists():
        risks = risks.annotate(
            severity_weight=Case(
                When(severity__iexact='Critical', then=Value(1)),
                When(severity__iexact='High', then=Value(2)),
                When(severity__iexact='Medium', then=Value(3)),
                When(severity__iexact='Low', then=Value(4)),
                When(severity__iexact='Info', then=Value(5)),
                When(severity__iexact='Informational', then=Value(5)),
                default=Value(6),
                output_field=IntegerField(),
            )
        ).order_by('severity_weight', '-report__completed')
    
    paginator = Paginator(risks, 20)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
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
        # Add our new permission variables here:
        'is_admin': is_admin,
        'can_resolve_risk': can_resolve_risk,
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
@require_POST
def resolve_risk(request, risk_id):
    """AJAX endpoint to mark a risk as resolved (archived)"""
    user = request.user
    
    try:
        risk = Risk.objects.get(risk_id=risk_id)
        user_org = user.organization
        
        # 1. Verify the user belongs to the same organization as the risk
        if not user_org or risk.organization != user_org:
            return JsonResponse({"error": "Unauthorized"}, status=403)
            
        # 2. Verify the user has permission to resolve (Admin OR has permission flag)
        first_user = User.objects.filter(organization=user_org).order_by('date_joined').first()
        is_admin = (first_user == user)
        can_resolve = user.has_perm('api.can_resolve_risk')
        
        if not (is_admin or can_resolve):
            return JsonResponse({"error": "You do not have permission to resolve risks."}, status=403)
        
        # Archive the risk
        risk.is_archived = True
        risk.save()
        
        return JsonResponse({"success": True})
        
    except Risk.DoesNotExist:
        return JsonResponse({"error": "Risk not found"}, status=404)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

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
    """
    Renders the full AI-generated report from the encrypted JSON field.

    Encryption note: report.report_text is an EncryptedJSONField. Django's
    ORM calls from_db_value() automatically on load, so report.report_text
    arrives here as a plain Python dict — no manual decryption needed.

    We build a risk_map {risk_name: risk_id} from the database so that each
    vulnerability card in the template can link to its risk detail page.
    """
    try:
        report = Report.objects.get(report_id=report_id)
    except Report.DoesNotExist:
        messages.error(request, "Report not found.")
        return redirect('report_list')

    # ── Permission check ──────────────────────────────────────────────────────
    try:
        user_org = request.user.organization
        if not user_org or report.organization != user_org:
            messages.error(request, "You don't have permission to view this report.")
            return redirect('report_list')
    except Exception:
        messages.error(request, "Unable to verify permissions.")
        return redirect('report_list')

    # ── Parse the (already-decrypted) JSON ───────────────────────────────────
    raw = report.report_text or {}
    if isinstance(raw, str):
        import json as _json
        try:
            raw = _json.loads(raw)
        except Exception:
            raw = {}

    report_items = raw.get('report', [])
    report_item  = report_items[0] if report_items else {}

    # ── Extract sections in the display order we want ─────────────────────────
    overview      = report_item.get('Overview', {})
    observations  = report_item.get('Observations', [])
    questionnaire = report_item.get('Questionnaire Review', {})
    risks_section = report_item.get('Risks & Recommendations', {})
    conclusion    = report_item.get('Conclusion', '')

    summary   = risks_section.get('Summary', '')
    raw_vulns = risks_section.get('Vulnerabilities Found', [])

    # ── Build a name → risk_id map from the database ──────────────────────────
    # This lets each vulnerability card link to its detail page.
    risk_map = {
        risk.risk_name: str(risk.risk_id)
        for risk in Risk.objects.filter(report=report)
    }

    # ── Flatten vulnerability dicts and attach the DB risk_id if found ────────
    SEVERITY_ORDER = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Info': 5}

    vulnerabilities = sorted(
        [
            {
                'risk':              v.get('Risk', ''),
                'overview':          v.get('Overview', ''),
                'severity':          v.get('Severity', 'Info'),
                'affected_elements': v.get('Affected Elements', []),
                'easy_fix':          v.get('Recommendation', {}).get('easy_fix', ''),
                'long_term_fix':     v.get('Recommendation', {}).get('long_term_fix', ''),
                # Look up the DB risk_id so the template can build the URL
                'risk_id':           risk_map.get(v.get('Risk', ''), None),
            }
            for v in raw_vulns
        ],
        key=lambda x: SEVERITY_ORDER.get(x['severity'], 6),
    )

    obs_list = [
        {
            'name':              o.get('Observation', ''),
            'overview':          o.get('Overview', ''),
            'affected_elements': o.get('Affected Elements', []),
        }
        for o in observations
    ]

    # only for showing json in report_detail.html, feel free to delete when done
    # raw_json = json.dumps(report.report_text, indent=2, default=str)

    context = {
        'report':          report,
        'overview':        overview,
        'observations':    obs_list,
        'questionnaire':   questionnaire,
        'summary':         summary,
        'vulnerabilities': vulnerabilities,
        'conclusion':      conclusion,
        'total_vulns':     len(vulnerabilities),
        # 'raw_json': raw_json, # for viewing json, can remove later
    }
    return render(request, 'api/report_detail.html', context)

@login_required
def download_report_pdf(request, report_id):
    """Return report data as JSON for pdfmake generation on the client side."""
    try:
        report = Report.objects.get(report_id=report_id)
    except Report.DoesNotExist:
        messages.error(request, "Report not found.")
        return redirect('report_list')

    # Permission check
    try:
        user_org = request.user.organization
        if not user_org or report.organization != user_org:
            messages.error(request, "You don't have permission to download this report.")
            return redirect('report_list')
    except Exception:
        messages.error(request, "Unable to verify permissions.")
        return redirect('report_list')

    # Extract report data from encrypted JSON field
    report_data = report.report_text
    if isinstance(report_data, str):
        import json
        report_data = json.loads(report_data)

    report_items = report_data.get('report', [])
    report_item = report_items[0] if report_items else {}

    # Prepare data for frontend PDF generation
    pdf_data = {
        'report_name': report.report_name,
        'report_id': str(report.report_id),
        'report_date': report.completed.strftime('%B %d, %Y'),
        'user_created': report.user_created.username,
        'overview': report_item.get('Overview', {}),
        'observations': report_item.get('Observations', []),
        'questionnaire': report_item.get('Questionnaire Review', {}),
        'summary': report_item.get('Risks & Recommendations', {}).get('Summary', ''),
        'vulnerabilities': report_item.get('Risks & Recommendations', {}).get('Vulnerabilities Found', []),
        'conclusion': report_item.get('Conclusion', ''),
    }

    return JsonResponse(pdf_data)

@login_required
def scan(request):
    """Display scan page"""
    return render(request, 'scan.html')

@login_required
def download_scanner_exe(request):
    """
    Serves the NetworkScanner.exe file as a download.
    Place the built exe at: api/assets/scanner/NetworkScanner.exe
    """
    import os
    from django.http import FileResponse, Http404

    exe_path = os.path.join(
        settings.BASE_DIR, 'api', 'assets', 'scanner', 'NetworkScanner.exe'
    )

    if not os.path.exists(exe_path):
        # Exe not built yet — tell the user clearly rather than a generic error
        return HttpResponse(
            "<h2>Scanner not yet available.</h2>"
            "<p>The scanner executable has not been built yet. "
            "Please contact your administrator.</p>",
            status=503,
            content_type='text/html',
        )

    response = FileResponse(
        open(exe_path, 'rb'),
        as_attachment=True,
        filename='NetworkScanner.exe',
        content_type='application/octet-stream',
    )
    return response


## DEBUG
from django.core.mail import send_mail
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def test_sendgrid(request):
    if request.method == 'POST':
        try:
            send_mail(
                'Test Email from SendGrid',
                'This is a test email sent via SendGrid on Heroku.',
                settings.DEFAULT_FROM_EMAIL,
                [request.POST.get('email')],
                fail_silently=False,
            )
            return JsonResponse({'success': True, 'message': 'Email sent!'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    return JsonResponse({'error': 'POST only'}, status=405)