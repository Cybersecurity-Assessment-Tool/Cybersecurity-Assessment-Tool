from functools import lru_cache
from urllib.parse import quote, urlencode
from urllib.request import Request as UrlRequest, urlopen
import sys
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
from .models import Invitation, Organization, User, Report, Risk, Scan, generate_email_hash
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
from django.contrib.auth.decorators import login_required, permission_required
import secrets

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
                **_get_google_oauth_context(),
            }
            return render(request, 'registration/invite_signup.html', context)
    else:
        # GET request - initialize the form (optionally prefilled from Google fallback)
        google_prefill = request.session.pop('google_invite_prefill', None) or {}
        form = InvitationSignupForm(initial={
            'email': invitation.recipient_email,
            'first_name': google_prefill.get('first_name', ''),
            'last_name': google_prefill.get('last_name', ''),
        })
    
    # Pass 'email' into the context so the {{ email }} template variable renders correctly
    context = {
        'form': form,
        'email': invitation.recipient_email,
        'organization': invitation.organization.org_name,
        **_get_google_oauth_context(),
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

def _get_microsoft_oauth_base_url():
    """Optional absolute base URL for local Microsoft OAuth flows"""
    return (getattr(settings, 'MICROSOFT_OAUTH_REDIRECT_BASE_URL', '') or '').strip().rstrip('/')


def _get_google_oauth_context():
    """Shared social OAuth configuration for auth templates."""
    google_client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '').strip()
    microsoft_client_id = getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', '').strip()
    return {
        'google_oauth_enabled': bool(google_client_id),
        'google_oauth_client_id': google_client_id,
        'microsoft_oauth_enabled': bool(microsoft_client_id),
        'microsoft_oauth_client_id': microsoft_client_id,
        'microsoft_oauth_base_url': _get_microsoft_oauth_base_url(),
    }


def _get_login_context(form=None):
    """Shared context for rendering the login page."""
    google_client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '').strip()
    
    # Add the Microsoft fetcher:
    microsoft_client_id = getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', '').strip()
    
    return {
        'form': form or AuthenticationForm(),
        'google_oauth_enabled': bool(google_client_id),
        'google_oauth_client_id': google_client_id,
        
        # Pass the Microsoft variables to the template:
        'microsoft_oauth_enabled': bool(microsoft_client_id),
        'microsoft_oauth_client_id': microsoft_client_id,
    }


def _build_login_otp_response(request, user, message='OTP sent to your email'):
    """Start the existing email OTP challenge for a successful login attempt."""
    request.session['pending_user_id'] = user.id

    from api.utils.send_otp_mail import generate_otp
    otp = generate_otp()

    queue_email('otp', user.email, {'otp': otp})
    print(f"Queued OTP email for {user.email}: {otp}")

    request.session['login_otp'] = otp
    request.session['login_otp_created'] = time.time()
    request.session['login_email'] = user.email

    return {
        'success': True,
        'requires_otp': True,
        'email': user.email,
        'message': message,
    }


def _build_oauth_absolute_uri(request, route_name, base_url=''):
    """Build an absolute URI for OAuth routes, with an optional local override."""
    if base_url:
        return f"{base_url}{reverse(route_name)}"
    return request.build_absolute_uri(reverse(route_name))


def _get_google_redirect_uri(request):
    """Build the absolute callback URI for the classic Google OAuth redirect flow."""
    return _build_oauth_absolute_uri(request, 'google_oauth_callback')


def _exchange_google_code(request, code):
    """Exchange an authorization code for a verified Google token payload."""
    client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '').strip()
    client_secret = (getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', '') or '').strip()
    if not client_id or not client_secret:
        raise ValueError('Google OAuth is not fully configured for this environment.')

    payload = urlencode({
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': _get_google_redirect_uri(request),
        'grant_type': 'authorization_code',
    }).encode('utf-8')

    token_request = UrlRequest(
        'https://oauth2.googleapis.com/token',
        data=payload,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )

    try:
        with urlopen(token_request, timeout=15) as token_response:
            token_data = json.loads(token_response.read().decode('utf-8'))
    except Exception as exc:
        raise ValueError('Google sign-in could not be completed.') from exc

    raw_id_token = (token_data.get('id_token') or '').strip()
    if not raw_id_token:
        raise ValueError('Google did not return an ID token for this request.')

    try:
        return id_token.verify_oauth2_token(
            raw_id_token,
            google_requests.Request(),
            client_id,
        )
    except ValueError as exc:
        raise ValueError('Google sign-in could not be verified.') from exc


def _get_microsoft_redirect_uri(request):
    """Build the absolute callback URI for the Microsoft OAuth redirect flow."""
    return _build_oauth_absolute_uri(
        request,
        'microsoft_oauth_callback',
        _get_microsoft_oauth_base_url(),
    )


def _get_microsoft_tenant_id():
    return (getattr(settings, 'MICROSOFT_OAUTH_TENANT_ID', 'organizations') or 'organizations').strip()


@lru_cache(maxsize=4)
def _get_microsoft_openid_config(tenant_id):
    metadata_url = (
        f"https://login.microsoftonline.com/{quote(tenant_id, safe='')}/v2.0/.well-known/openid-configuration"
    )
    metadata_request = UrlRequest(metadata_url, headers={'Accept': 'application/json'})
    try:
        with urlopen(metadata_request, timeout=15) as metadata_response:
            return json.loads(metadata_response.read().decode('utf-8'))
    except Exception as exc:
        raise ValueError('Microsoft sign-in is temporarily unavailable.') from exc


def _extract_microsoft_identity(token_payload):
    email = (
        token_payload.get('email')
        or token_payload.get('preferred_username')
        or token_payload.get('upn')
        or ''
    ).strip().lower()
    return {
        'email': email,
        'first_name': (token_payload.get('given_name') or '').strip(),
        'last_name': (token_payload.get('family_name') or '').strip(),
    }


def _exchange_microsoft_code(request, code):
    """Exchange an authorization code for a verified Microsoft/Office 365 token payload."""
    client_id = getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', '').strip()
    client_secret = (getattr(settings, 'MICROSOFT_OAUTH_CLIENT_SECRET', '') or '').strip()
    if not client_id or not client_secret:
        raise ValueError('Microsoft OAuth is not fully configured for this environment.')

    tenant_id = _get_microsoft_tenant_id()
    openid_config = _get_microsoft_openid_config(tenant_id)

    payload = urlencode({
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'redirect_uri': _get_microsoft_redirect_uri(request),
        'grant_type': 'authorization_code',
        'scope': 'openid profile email',
    }).encode('utf-8')

    token_request = UrlRequest(
        openid_config['token_endpoint'],
        data=payload,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )

    try:
        with urlopen(token_request, timeout=15) as token_response:
            token_data = json.loads(token_response.read().decode('utf-8'))
    except Exception as exc:
        raise ValueError('Microsoft sign-in could not be completed.') from exc

    raw_id_token = (token_data.get('id_token') or '').strip()
    if not raw_id_token:
        raise ValueError('Microsoft did not return an ID token for this request.')

    try:
        token_payload = id_token.verify_token(
            raw_id_token,
            google_requests.Request(),
            audience=client_id,
            certs_url=openid_config['jwks_uri'],
        )
    except ValueError as exc:
        raise ValueError('Microsoft sign-in could not be verified.') from exc

    issuer = (token_payload.get('iss') or '').strip()
    if issuer and not (
        issuer.startswith('https://login.microsoftonline.com/')
        or issuer.startswith('https://sts.windows.net/')
    ):
        raise ValueError('Microsoft sign-in could not be verified.')

    return token_payload


def google_oauth_start(request):
    """Start a classic browser-redirect Google OAuth flow as a fallback when GIS popup mode fails."""
    client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '').strip()
    if not client_id:
        messages.error(request, 'Google OAuth is not configured for this environment.')
        return redirect(request.GET.get('next') or reverse('login'))

    flow = (request.GET.get('flow') or 'login').strip().lower()
    next_url = request.GET.get('next') or reverse('login')
    expected_email = (request.GET.get('expected_email') or '').strip().lower()

    state = secrets.token_urlsafe(32)
    request.session['google_oauth_state'] = state
    request.session['google_oauth_flow'] = flow
    request.session['google_oauth_next'] = next_url
    request.session['google_oauth_expected_email'] = expected_email

    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode({
        'client_id': client_id,
        'redirect_uri': _get_google_redirect_uri(request),
        'response_type': 'code',
        'scope': 'openid email profile',
        'prompt': 'select_account',
        'state': state,
    })
    return redirect(auth_url)


def google_oauth_callback(request):
    """Handle the classic browser-redirect Google OAuth callback."""
    next_url = request.session.pop('google_oauth_next', reverse('login'))
    flow = request.session.pop('google_oauth_flow', 'login')
    expected_email = request.session.pop('google_oauth_expected_email', '')
    saved_state = request.session.pop('google_oauth_state', None)

    if request.GET.get('error'):
        messages.error(request, 'Google sign-in was cancelled or denied.')
        return redirect(next_url)

    code = request.GET.get('code')
    state = request.GET.get('state')
    if not code or not saved_state or state != saved_state:
        messages.error(request, 'Google sign-in could not be validated. Please try again.')
        return redirect(next_url)

    try:
        token_payload = _exchange_google_code(request, code)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect(next_url)

    email = (token_payload.get('email') or '').strip().lower()
    if not email or not token_payload.get('email_verified'):
        messages.error(request, 'Your Google email address is not verified.')
        return redirect(next_url)

    if expected_email and email != expected_email:
        messages.error(
            request,
            f'Please use the Google account that matches the invited email address: {expected_email}.',
        )
        return redirect(next_url)

    first_name = (token_payload.get('given_name') or '').strip()
    last_name = (token_payload.get('family_name') or '').strip()

    if flow == 'login':
        user = User.objects.filter(email_hash=generate_email_hash(email)).first()
        if user is None:
            messages.error(request, 'No approved account is linked to this Google email address.')
            return redirect(next_url)
        if not user.is_active:
            messages.error(request, 'Your account is pending approval. Please contact your administrator.')
            return redirect(next_url)

        updated = False
        if first_name and not user.first_name:
            user.first_name = first_name
            updated = True
        if last_name and not user.last_name:
            user.last_name = last_name
            updated = True
        if updated:
            user.save()

        if getattr(settings, 'GOOGLE_OAUTH_REQUIRE_OTP', True):
            _build_login_otp_response(
                request,
                user,
                message='OTP sent to your email to complete Google sign-in.',
            )
            request.session['google_login_requires_otp'] = True
            return redirect(reverse('login'))

        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
        return redirect(reverse('login_redirect'))

    if flow == 'invite':
        request.session['social_signup_provider'] = 'Google'
        request.session['google_signup_verified_email'] = email
        request.session['google_invite_prefill'] = {
            'first_name': first_name,
            'last_name': last_name,
        }
        messages.success(request, 'Google verified the invited email. Please finish the form to create the account.')
        return redirect(next_url)

    request.session['social_signup_provider'] = 'Google'
    request.session['verified_email'] = email
    request.session['email_verified'] = True
    request.session['google_signup_verified_email'] = email
    request.session[f'registration_verified_{email}'] = True
    request.session['google_signup_prefill'] = {
        'email': email,
        'first_name': first_name,
        'last_name': last_name,
    }
    messages.success(request, 'Google verified your email. Please finish the form and submit it for approval. A separate password is optional for this signup.')
    return redirect(next_url)


def microsoft_oauth_start(request):
    """Start the Microsoft/Office 365 OAuth redirect flow."""
    client_id = getattr(settings, 'MICROSOFT_OAUTH_CLIENT_ID', '').strip()
    if not client_id:
        messages.error(request, 'Microsoft OAuth is not configured for this environment.')
        return redirect(request.GET.get('next') or reverse('login'))

    flow = (request.GET.get('flow') or 'login').strip().lower()
    next_url = request.GET.get('next') or reverse('login')
    expected_email = (request.GET.get('expected_email') or '').strip().lower()

    state = secrets.token_urlsafe(32)
    request.session['microsoft_oauth_state'] = state
    request.session['microsoft_oauth_flow'] = flow
    request.session['microsoft_oauth_next'] = next_url
    request.session['microsoft_oauth_expected_email'] = expected_email

    tenant_id = _get_microsoft_tenant_id()
    auth_url = (
        f"https://login.microsoftonline.com/{quote(tenant_id, safe='')}/oauth2/v2.0/authorize?"
        + urlencode({
            'client_id': client_id,
            'redirect_uri': _get_microsoft_redirect_uri(request),
            'response_type': 'code',
            'response_mode': 'query',
            'scope': 'openid profile email',
            'prompt': 'select_account',
            'state': state,
        })
    )
    return redirect(auth_url)


def microsoft_oauth_callback(request):
    """Handle the classic browser-redirect Microsoft/Office 365 OAuth callback."""
    next_url = request.session.pop('microsoft_oauth_next', reverse('login'))
    flow = request.session.pop('microsoft_oauth_flow', 'login')
    expected_email = request.session.pop('microsoft_oauth_expected_email', '')
    saved_state = request.session.pop('microsoft_oauth_state', None)

    if request.GET.get('error'):
        messages.error(request, 'Microsoft sign-in was cancelled or denied.')
        return redirect(next_url)

    code = request.GET.get('code')
    state = request.GET.get('state')
    if not code or not saved_state or state != saved_state:
        messages.error(request, 'Microsoft sign-in could not be validated. Please try again.')
        return redirect(next_url)

    try:
        token_payload = _exchange_microsoft_code(request, code)
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect(next_url)

    identity = _extract_microsoft_identity(token_payload)
    email = identity['email']
    first_name = identity['first_name']
    last_name = identity['last_name']

    if not email:
        messages.error(request, 'Microsoft sign-in did not provide a usable email address.')
        return redirect(next_url)

    if expected_email and email != expected_email:
        messages.error(
            request,
            f'Please use the Microsoft account that matches the invited email address: {expected_email}.',
        )
        return redirect(next_url)

    if flow == 'login':
        user = User.objects.filter(email_hash=generate_email_hash(email)).first()
        if user is None:
            messages.error(request, 'No approved account is linked to this Microsoft email address.')
            return redirect(next_url)
        if not user.is_active:
            messages.error(request, 'Your account is pending approval. Please contact your administrator.')
            return redirect(next_url)

        updated = False
        if first_name and not user.first_name:
            user.first_name = first_name
            updated = True
        if last_name and not user.last_name:
            user.last_name = last_name
            updated = True
        if updated:
            user.save()

        if getattr(settings, 'MICROSOFT_OAUTH_REQUIRE_OTP', getattr(settings, 'GOOGLE_OAUTH_REQUIRE_OTP', True)):
            _build_login_otp_response(
                request,
                user,
                message='OTP sent to your email to complete Microsoft sign-in.',
            )
            request.session['google_login_requires_otp'] = True
            return redirect(reverse('login'))

        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
        return redirect(reverse('login_redirect'))

    if flow == 'invite':
        request.session['social_signup_provider'] = 'Microsoft'
        request.session['google_signup_verified_email'] = email
        request.session['google_invite_prefill'] = {
            'first_name': first_name,
            'last_name': last_name,
        }
        messages.success(request, 'Microsoft verified the invited email. Please finish the form to create the account.')
        return redirect(next_url)

    request.session['social_signup_provider'] = 'Microsoft'
    request.session['verified_email'] = email
    request.session['email_verified'] = True
    request.session['google_signup_verified_email'] = email
    request.session[f'registration_verified_{email}'] = True
    request.session['google_signup_prefill'] = {
        'email': email,
        'first_name': first_name,
        'last_name': last_name,
    }
    messages.success(request, 'Microsoft verified your email. Please finish the form and submit it for approval. A separate password is optional for this signup.')
    return redirect(next_url)


@require_POST
def resend_login_otp(request):
    """Resend the login OTP using the pending user already stored in session."""
    user_id = request.session.get('pending_user_id')
    if not user_id:
        return JsonResponse({'success': False, 'error': 'No pending login session found.'}, status=400)

    user = User.objects.filter(id=user_id).first()
    if user is None:
        return JsonResponse({'success': False, 'error': 'Pending login user no longer exists.'}, status=404)

    return JsonResponse(
        _build_login_otp_response(
            request,
            user,
            message='OTP sent to your email',
        )
    )


@require_POST
def google_oauth_signup(request):
    """Verify a Google account for signup without creating or logging the user in."""
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
            'error': 'Invalid signup payload.',
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
            'error': 'Google sign-up could not be verified.',
        }, status=400)

    email = (token_payload.get('email') or '').strip().lower()
    if not email or not token_payload.get('email_verified'):
        return JsonResponse({
            'success': False,
            'error': 'Your Google email address is not verified.',
        }, status=403)

    expected_email = (data.get('expected_email') or '').strip().lower()
    if expected_email and email != expected_email:
        return JsonResponse({
            'success': False,
            'error': f'Please use the Google account that matches your invited email address: {expected_email}.',
        }, status=403)

    purpose = (data.get('purpose') or 'registration').strip().lower()
    request.session['social_signup_provider'] = 'Google'
    request.session['verified_email'] = email
    request.session['email_verified'] = True
    request.session['google_signup_verified_email'] = email
    request.session[f'{purpose}_verified_{email}'] = True

    return JsonResponse({
        'success': True,
        'message': 'Google verified your email. Please finish the form and submit it to continue. A separate password is optional for this signup.',
        'email': email,
        'first_name': (token_payload.get('given_name') or '').strip(),
        'last_name': (token_payload.get('family_name') or '').strip(),
    })


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

    if getattr(settings, 'GOOGLE_OAUTH_REQUIRE_OTP', True):
        return JsonResponse(
            _build_login_otp_response(
                request,
                user,
                message='OTP sent to your email to complete Google sign-in.',
            )
        )

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
                    return JsonResponse(
                        _build_login_otp_response(
                            request,
                            user,
                            message='OTP sent to your email',
                        )
                    )
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

from django.core.paginator import Paginator
from django.contrib import messages

@login_required
def dashboard(request):
    """Display dashboard page with aggregated data from the most recent
    completed scan for each scan type (tcp, udp, email, infra).
    
    For each of the 4 scan types, we find the latest completed Scan that
    included that type, collect its report, and pull all unarchived risks
    from those reports. This prevents a partial re-scan from hiding
    findings that were discovered by a different scan type earlier."""
    user = request.user
    organization = user.organization

    vulnerabilities = []
    source_reports = []  # reports contributing to the dashboard

    if organization:
        # scan_types_run is stored as [tcp, udp, email, infra] with 1/0 flags.
        # Index position maps: 0=tcp, 1=udp, 2=email, 3=infra
        SCAN_TYPE_INDICES = {
            'tcp': 0,
            'udp': 1,
            'email': 2,
            'infra': 3,
        }

        # For each scan type, find the latest completed scan that included it
        report_ids = set()
        for type_name, idx in SCAN_TYPE_INDICES.items():
            latest_scan = (
                Scan.objects.filter(
                    organization=organization,
                    status=Scan.Status.COMPLETE,
                    report__isnull=False,
                )
                .exclude(scan_types_run=[])
                .order_by('-scan_completed_at')
            )
            # Filter to scans that included this type
            # scan_types_run[idx] == 1
            for scan in latest_scan:
                types = scan.scan_types_run
                if isinstance(types, list) and len(types) > idx and types[idx]:
                    report_ids.add(scan.report_id)
                    break

        # Also include any completed scans with empty scan_types_run
        # (legacy scans before this field existed — treat as all-types)
        legacy_scan = (
            Scan.objects.filter(
                organization=organization,
                status=Scan.Status.COMPLETE,
                report__isnull=False,
                scan_types_run=[],
            )
            .order_by('-scan_completed_at')
            .first()
        )
        if legacy_scan:
            report_ids.add(legacy_scan.report_id)

        if report_ids:
            # Fetch unarchived risks from all the contributing reports
            risks = Risk.objects.filter(
                organization=organization,
                report_id__in=report_ids,
                is_archived=False,
            )

            seen_risk_names = set()
            for risk in risks:
                # Deduplicate by risk name — if the same finding appears
                # in multiple reports, keep only one instance
                key = risk.risk_name.strip().lower()
                if key in seen_risk_names:
                    continue
                seen_risk_names.add(key)

                vulnerabilities.append({
                    'severity': risk.severity,
                    'risk_name': risk.risk_name,
                    'overview': risk.overview,
                    'url': reverse('risk_detail', args=[risk.risk_id]),
                })

            source_reports = list(
                Report.objects.filter(report_id__in=report_ids)
                .order_by('-completed')
            )

    latest_report = source_reports[0] if source_reports else None
    report_date = None
    if latest_report:
        report_date = latest_report.completed or latest_report.started

    context = {
        'vulnerabilities_json': vulnerabilities,
        'has_data': len(vulnerabilities) > 0,
        'latest_report': latest_report,
        'source_reports': source_reports,
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
    
    paginator = Paginator(risks, 10)
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
        risk.resolved_by = user
        risk.resolved_at = timezone.now()
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
    """Renders the full AI-generated report from the encrypted JSON field."""
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
    except Exception:
        messages.error(request, "Unable to verify permissions.")
        return redirect('report_list')

    raw = report.report_text or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}

    report_items = raw.get('report', [])
    report_item = report_items[0] if report_items else {}

    overview = report_item.get('Overview', {})
    observations = report_item.get('Observations', [])
    questionnaire = report_item.get('Questionnaire Review', {})
    risks_section = report_item.get('Risks & Recommendations', {})
    conclusion = report_item.get('Conclusion', '')
    summary = risks_section.get('Summary', '')
    raw_vulns = risks_section.get('Vulnerabilities Found', [])
    # Extract Technical Scan Results stored by gemini_client at report-gen time.
    raw_sf = report_item.get('Scan Findings', {})
    port_findings = []

    # Deep-parse Scan Findings for Report Detail page only
    scan_findings_raw = raw_sf
    if scan_findings_raw and isinstance(scan_findings_raw, dict):
        for key, val in scan_findings_raw.items():
            if isinstance(val, str):
                val_stripped = val.strip()
                if (val_stripped.startswith('{') and val_stripped.endswith('}')) or \
                   (val_stripped.startswith('[') and val_stripped.endswith(']')):
                    try:
                        scan_findings_raw[key] = json.loads(val_stripped)
                    except json.JSONDecodeError:
                        pass
        scan_findings = json.dumps(scan_findings_raw, indent=2)
    else:
        scan_findings = None

    risk_map = {risk.risk_name: str(risk.risk_id) for risk in Risk.objects.filter(report=report)}
    
    if isinstance(raw_sf, dict) and raw_sf:
        port_findings = raw_sf.get('findings', [])
 
    risk_map = {
        risk.risk_name: str(risk.risk_id)
        for risk in Risk.objects.filter(report=report)
    }

    # ── Bulletproof parsing of AI vulnerability outputs ──────────
    SEVERITY_ORDER = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Info': 5}

    # Construct sections pertaining to the vulnerabilities found
    vulnerabilities = sorted(
        [
            {
                'risk': v.get('Risk', ''),
                'overview': v.get('Overview', ''),
                'severity': v.get('Severity', 'Info'),
                'affected_elements': v.get('Affected Elements', []),
                'easy_fix': v.get('Recommendation', {}).get('easy_fix', ''),
                'long_term_fix': v.get('Recommendation', {}).get('long_term_fix', ''),
                'risk_id': risk_map.get(v.get('Risk', ''), None),
            }
            for v in raw_vulns
        ],
        key=lambda x: SEVERITY_ORDER.get(x['severity'], 6),
    )

    obs_list = [
        {
            'name': o.get('Observation', ''),
            'overview': o.get('Overview', ''),
            'affected_elements': o.get('Affected Elements', []),
        }
        for o in observations
    ]

    # Pass all parsed data to the template for rendering
    context = {
        'report': report,
        'overview': overview,
        'observations': obs_list,
        'questionnaire': questionnaire,
        'summary': summary,
        'vulnerabilities': vulnerabilities,
        'scan_findings': scan_findings,
        'port_findings': port_findings,
        'conclusion': conclusion,
        'total_vulns': len(vulnerabilities),
    }
    return render(request, 'api/report_detail.html', context)

@login_required
def download_report_pdf(request, report_id):
    """Return report data as JSON for pdfmake generation on the client side."""
    try:
        report = Report.objects.get(report_id=report_id)
    except Report.DoesNotExist:
        return JsonResponse({'error': 'Report not found.'}, status=404)

    try:
        user_org = request.user.organization
        if not user_org or report.organization != user_org:
            return JsonResponse({'error': 'Unauthorized.'}, status=403)
    except Exception:
        return JsonResponse({'error': 'Permission error.'}, status=403)

    report_data = report.report_text
    if isinstance(report_data, str):
        try:
            report_data = json.loads(report_data)
        except Exception:
            report_data = {}

    report_items = report_data.get('report', [])
    report_item = report_items[0] if report_items else {}

    # ── ✨ BULLETPROOF AI PARSING (Same as above) ✨ ──────────
    raw_vulns = report_item.get('Risks & Recommendations', {}).get('Vulnerabilities Found', [])
    pdf_vulns = []
    
    for v in raw_vulns:
        if not isinstance(v, dict):
            continue
            
        v_lower = {str(k).lower().strip().replace('_', ' '): val for k, val in v.items()}
        
        risk_name = v_lower.get('risk') or v_lower.get('risk name') or v_lower.get('name') or 'Unknown Risk'
        overview_text = v_lower.get('overview') or v_lower.get('description') or v_lower.get('details') or 'No description provided.'
        
        severity_val = v_lower.get('severity') or 'Info'
        if isinstance(severity_val, str):
            severity_val = severity_val.replace('"', '').replace(',', '').replace('[', '').replace(']', '').strip().capitalize()
        
        elements = v_lower.get('affected elements') or v_lower.get('elements') or []
        if isinstance(elements, str):
            elements = [e.strip() for e in elements.split(',') if e.strip()]
            
        recs = v_lower.get('recommendation') or v_lower.get('recommendations') or {}
        if isinstance(recs, dict):
            r_lower = {str(k).lower().strip().replace('_', ' '): val for k, val in recs.items()}
            easy_fix = r_lower.get('easy fix') or r_lower.get('quick fix') or ''
            long_term_fix = r_lower.get('long term fix') or ''
        elif isinstance(recs, str):
            easy_fix, long_term_fix = recs, ''
        else:
            easy_fix, long_term_fix = '', ''
            
        pdf_vulns.append({
            'risk': risk_name,
            'overview': overview_text,
            'severity': severity_val,
            'affected_elements': elements,
            'easy_fix': easy_fix,
            'long_term_fix': long_term_fix
        })

    # Changed how the scan findings are extracted
    raw_sf = report_item.get('Scan Findings', {})
    port_findings_pdf = []
 
    if isinstance(raw_sf, dict) and raw_sf:
        port_findings_pdf = raw_sf.get('findings', [])
 
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
        'port_findings': port_findings_pdf,
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
                getattr(settings, 'ADMIN_EMAIL_INBOX', '') or settings.DEFAULT_FROM_EMAIL,
                [request.POST.get('email')],
                fail_silently=False,
            )
            return JsonResponse({'success': True, 'message': 'Email sent!'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    return JsonResponse({'error': 'POST only'}, status=405)