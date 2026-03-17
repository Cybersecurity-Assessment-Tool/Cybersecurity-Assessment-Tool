from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView
from .forms import CustomUserCreationForm

class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    success_url = reverse_lazy("login")
    template_name = "registration/signup.html"

### Test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

class UserDetailView(LoginRequiredMixin, TemplateView):
    template_name = "accounts/user_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user
        return context
    
from django.shortcuts import render
    
def settings(request):
    """Display settings page"""
    return render(request, 'accounts/settings.html')

def upload_profile_image(request):
    """Display upload profile image page"""
    return render(request, 'accounts/upload_profile_image.html')

def organization(request):
    """Display organization page"""
    return render(request, 'accounts/organization.html')

# TEST 2
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from api.models import Invitation, OrganizationQuestionnaire
import random
import string


# Public Registration View
def public_register(request):
    """Public registration page for new organizations"""
    if request.method == 'POST':
        # TODO: Implement registration logic
        # - Get form data (company_name, email, password)
        # - Create organization with status='pending'
        # - Create user as organization admin with is_active=False
        # - Send notification email to admins
        # - Redirect to waiting page
        
        company_name = request.POST.get('company_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        # Placeholder - replace with actual implementation
        messages.success(request, 'Registration submitted successfully!')
        return redirect('accounts:waiting')
    
    return render(request, 'registration/public_register.html')

# Waiting Page
def waiting_page(request):
    """Page shown after registration while awaiting approval"""
    # TODO: Get organization status from database
    context = {
        'company_name': request.session.get('company_name', 'Your Organization'),
        'email': request.session.get('email', ''),
        'submitted_at': timezone.now(),
    }
    return render(request, 'registration/waiting.html', context)

# OTP Endpoints
def send_otp(request):
    """Send OTP code to email for verification"""
    if request.method == 'POST':
        email = request.POST.get('email')
        purpose = request.POST.get('purpose', 'registration')
        
        # Generate 6-digit OTP
        otp = ''.join(random.choices(string.digits, k=6))
        
        # TODO: Store OTP in database with expiration
        # TODO: Send OTP email
        
        # For testing, print to console
        print(f"OTP for {email} ({purpose}): {otp}")
        
        # Store in session for testing
        request.session['otp_code'] = otp
        request.session['otp_email'] = email
        request.session['otp_purpose'] = purpose
        
        return JsonResponse({'success': True, 'message': 'OTP sent successfully'})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def verify_otp(request):
    """Verify OTP code"""
    if request.method == 'POST':
        email = request.POST.get('email')
        otp_code = request.POST.get('otp_code')
        purpose = request.POST.get('purpose', 'registration')
        
        # TODO: Check OTP from database
        # For testing, check against session
        stored_otp = request.session.get('otp_code')
        stored_email = request.session.get('otp_email')
        stored_purpose = request.session.get('otp_purpose')
        
        if (stored_otp == otp_code and 
            stored_email == email and 
            stored_purpose == purpose):
            # Mark as verified in session
            request.session[f'{purpose}_verified_{email}'] = True
            # Store the verified email
            request.session['verified_email'] = email
            request.session['email_verified'] = True
            return JsonResponse({'success': True, 'message': 'OTP verified successfully'})
        else:
            return JsonResponse({'error': 'Invalid OTP code'}, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

# Questionnaire Page
@login_required
def questionnaire(request):
    """First-time questionnaire for organization setup"""
    user = request.user
    if not user.organization:
        messages.error(request, "You are not associated with an organization.")
        return redirect('dashboard')
    
    # If questionnaire already completed, redirect to dashboard
    if user.organization.questionnaire_completed:
        return redirect('dashboard')
    
    if request.method == 'POST':
        # Process form data
        ip_address = request.POST.get('ip_address')
        has_security_policy = request.POST.get('has_security_policy') == 'on'
        conducts_regular_audits = request.POST.get('conducts_regular_audits') == 'on'
        has_incident_response = request.POST.get('has_incident_response') == 'on'
        uses_encryption = request.POST.get('uses_encryption') == 'on'
        
        # Validate IP address (basic)
        if not ip_address:
            messages.error(request, "IP address is required.")
            return render(request, 'registration/questionnaire.html')
        
        # Save to OrganizationQuestionnaire
        questionnaire, created = OrganizationQuestionnaire.objects.update_or_create(
            organization=user.organization,
            defaults={
                'ip_address': ip_address,
                'has_security_policy': has_security_policy,
                'conducts_regular_audits': conducts_regular_audits,
                'has_incident_response': has_incident_response,
                'uses_encryption': uses_encryption,
            }
        )
        
        # Mark organization questionnaire as completed
        user.organization.questionnaire_completed = True
        user.organization.save()
        
        messages.success(request, "Thank you for completing the setup questionnaire!")
        return redirect('dashboard')
    
    # GET request - show empty form
    return render(request, 'registration/questionnaire.html')

# Team Management API Endpoints
@login_required
def team_members(request):
    """Return list of team members for the current organization"""
    # TODO: Get actual team members from database
    if not request.user.organization:
        return JsonResponse({'members': []})
    
    # Placeholder data
    members = [
        {
            'username': request.user.username,
            'email': request.user.email,
            'role': 'Admin',
            'name': request.user.get_full_name() or request.user.username,
        }
    ]
    return JsonResponse({'members': members})

@login_required
def pending_invites(request):
    """Return list of pending invitations"""
    # TODO: Get actual pending invites from database
    # Placeholder data
    invites = []
    return JsonResponse({'invites': invites})

@login_required
def send_invitation(request):
    """Send invitation email to new team member"""
    if request.method == 'POST':
        email = request.POST.get('email')
        role = request.POST.get('role', 'analyst')
        
        # TODO: Create invitation record in database
        # TODO: Send invitation email
        
        messages.success(request, f'Invitation sent to {email}')
        return JsonResponse({'success': True})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@login_required
def resend_invitation(request):
    """Resend a pending invitation"""
    if request.method == 'POST':
        invite_id = request.POST.get('invite_id')
        # TODO: Find invitation and resend email
        return JsonResponse({'success': True})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@login_required
def cancel_invitation(request):
    """Cancel a pending invitation"""
    if request.method == 'POST':
        invite_id = request.POST.get('invite_id')
        # TODO: Update invitation status to 'cancelled'
        return JsonResponse({'success': True})
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def accept_invitation(request, token):
    """Handle invitation acceptance - redirect to signup with pre-filled email"""
    # TODO: Validate token and get invitation details
    # TODO: Redirect to signup with email pre-filled
    return redirect(f"{reverse('signup')}?email={Invitation.email}")

def check_registration_status(request):
    """AJAX endpoint to check if registration has been approved"""
    # TODO: Check organization status in database
    return JsonResponse({'status': 'pending'})
    
# from django.shortcuts import render, redirect, get_object_or_404
# from django.contrib.auth.decorators import login_required
# from django.contrib import messages
# from django.contrib.auth import get_user_model
# from django.views.decorators.http import require_POST
# from django.http import JsonResponse
# from .models import UserProfile
# from .forms import UserProfileForm, UserEmailForm, TwoFactorSetupForm

# User = get_user_model()

# @login_required
# def profile_settings(request):
#     """
#     Main profile settings view with tabbed interface.
#     Implements role-based views - different sections shown based on user role.
#     Includes save indicators through form dirty checking.
#     """
#     user = request.user
#     profile = user.profile
    
#     # Role-based view control
#     is_admin = profile.organization_role == 'admin'
#     is_analyst = profile.organization_role in ['admin', 'analyst']
    
#     # Initialize forms
#     profile_form = UserProfileForm(instance=profile, prefix='profile')
#     email_form = UserEmailForm(instance=user, prefix='email')
#     twofa_form = TwoFactorSetupForm(prefix='2fa')
    
#     # Handle form submissions
#     if request.method == 'POST':
#         active_tab = request.POST.get('active_tab', 'profile')
        
#         if 'update_profile' in request.POST:
#             profile_form = UserProfileForm(
#                 request.POST, 
#                 request.FILES, 
#                 instance=profile, 
#                 prefix='profile'
#             )
#             if profile_form.is_valid():
#                 profile_form.save()
#                 messages.success(request, 'Profile updated successfully!')
#                 return redirect(f'{request.path}?tab={active_tab}#')
        
#         elif 'update_email' in request.POST:
#             email_form = UserEmailForm(request.POST, instance=user, prefix='email')
#             if email_form.is_valid():
#                 email_form.save()
#                 messages.success(request, 'Email updated successfully!')
#                 return redirect(f'{request.path}?tab={active_tab}#')
        
#         elif 'setup_2fa' in request.POST:
#             # TODO: Implement actual 2FA setup
#             # This would involve:
#             # 1. Generating a secret key for the user
#             # 2. Displaying QR code for authenticator app
#             # 3. Verifying the code from the form
#             # 4. Enabling 2FA for the user
#             twofa_form = TwoFactorSetupForm(request.POST, prefix='2fa')
#             if twofa_form.is_valid():
#                 messages.info(request, '2FA setup is not yet implemented. This is a placeholder.')
#                 # In production, you'd use django-otp or pyotp
#                 # Example implementation:
#                 # import pyotp
#                 # secret = pyotp.random_base32()
#                 # user.totp_secret = secret
#                 # user.save()
#                 # Show QR code: pyotp.totp.TOTP(secret).provisioning_uri()
    
#     # Get active tab from query parameter
#     active_tab = request.GET.get('tab', 'profile')
    
#     context = {
#         'user': user,
#         'profile': profile,
#         'profile_form': profile_form,
#         'email_form': email_form,
#         'twofa_form': twofa_form,
#         'active_tab': active_tab,
#         'is_admin': is_admin,
#         'is_analyst': is_analyst,
#     }
    
#     return render(request, 'profiles/settings.html', context)

# @login_required
# @require_POST
# def upload_profile_image(request):
#     """
#     AJAX endpoint for profile image upload.
#     Provides immediate feedback without page reload.
#     """
#     try:
#         profile = request.user.profile
#         if 'profile_image' in request.FILES:
#             profile.profile_image = request.FILES['profile_image']
#             profile.save()
#             return JsonResponse({
#                 'success': True,
#                 'image_url': profile.profile_image.url
#             })
#     except Exception as e:
#         return JsonResponse({
#             'success': False,
#             'error': str(e)
#         }, status=400)

# @login_required
# def organization_members(request):
#     """
#     Phase 3: Organization member management view.
#     This is a placeholder UI that explains how the full feature would work.
#     """
#     user = request.user
    
#     # Role check - only admins should access this
#     if user.profile.organization_role != 'admin':
#         messages.error(request, 'You do not have permission to view this page.')
#         return redirect('profile_settings')
    
#     # TODO: Implement actual organization member management
#     # This would involve:
#     # 1. Creating an Organization model
#     # 2. Adding ForeignKey to UserProfile for organization
#     # 3. Creating invitation system with tokens
#     # 4. Managing member roles and permissions
    
#     # Placeholder member data
#     members = [
#         {
#             'user': user,
#             'role': 'Admin',
#             'status': 'Active',
#             'joined': '2024-01-15',
#         }
#     ]
    
#     context = {
#         'members': members,
#         'pending_invites': [],  # Placeholder for pending invitations
#     }
    
#     return render(request, 'profiles/organization.html', context)