from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView
from .forms import CustomUserCreationForm, InvitationSignupForm
from django.contrib.auth import get_user_model

User = get_user_model()

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
from django.contrib.auth.decorators import login_required
    
@login_required
def settings(request):
    """Display settings page with tabs"""
    user = request.user
    is_admin = False
    if user.organization:
        first_user = User.objects.filter(organization=user.organization).order_by('date_joined').first()
        is_admin = (first_user == user)
    context = {
        'is_admin': is_admin,
        'active_tab': request.GET.get('tab', 'profile'),
        # You may also need to pass profile forms if you restore them later
    }
    return render(request, 'accounts/settings.html', context)

def upload_profile_image(request):
    """Display upload profile image page"""
    return render(request, 'accounts/upload_profile_image.html')

def organization(request):
    """Display organization page"""
    return render(request, 'accounts/organization.html')

# TEST 2
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from api.models import Invitation
import random
import string
import uuid
import traceback
from api.utils.email_factory import send_email_by_type


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

# OTP Endpoints (generates OTP code and stores it in session)
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

# checks users input against the otp stored in session
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
        # Process form text inputs
        domain_name = request.POST.get('domain_name')
        ip_address = request.POST.get('ip_address')
        
        # Process form checkboxes (HTML checkboxes return 'on' if checked)
        mfa_email = request.POST.get('mfa_email') == 'on'
        mfa_computers = request.POST.get('mfa_computers') == 'on'
        mfa_sensitive_data = request.POST.get('mfa_sensitive_data') == 'on'
        has_aup = request.POST.get('has_aup') == 'on'
        training_new = request.POST.get('training_new_employees') == 'on'
        training_annual = request.POST.get('training_annual') == 'on'
        
        # Basic Validation
        if not ip_address or not domain_name:
            messages.error(request, "Domain name and IP address are required.")
            return render(request, 'registration/questionnaire.html')
        
        # Save directly to the existing Organization model fields
        org = user.organization
        org.website_domain = domain_name
        org.external_ip = ip_address
        org.require_mfa_email = mfa_email
        org.require_mfa_computer = mfa_computers
        org.require_mfa_sensitive_data = mfa_sensitive_data
        org.employee_acceptable_use_policy = has_aup
        org.training_new_employees = training_new
        org.training_once_per_year = training_annual
        
        # Mark organization questionnaire as completed
        org.questionnaire_completed = True
        org.save()
        
        messages.success(request, "Thank you for completing the setup questionnaire!")
        return redirect('dashboard')
    
    # GET request - show empty form
    return render(request, 'registration/questionnaire.html')

# Team Management API Endpoints
@login_required
def team_members(request):
    user = request.user
    if not user.organization:
        return JsonResponse({'members': []})
    members = User.objects.filter(organization=user.organization).order_by('date_joined')
    first_user = members.first()
    # Exclude the admin (first/oldest user) — they are the only one who can
    # reach this endpoint, so they should never appear in their own member list.
    regular_members = members.exclude(id=first_user.id) if first_user else members
    # Pre-fetch all invitations for this org in one query to avoid N+1 lookups.
    invitations = Invitation.objects.filter(organization=user.organization)
    role_map = {inv.recipient_email: inv.recipient_role for inv in invitations}
    data = []
    for member in regular_members:
        raw_role = role_map.get(member.email, 'member')
        data.append({
            'id': member.id,
            'username': member.username,
            'email': member.email,
            'role': raw_role.capitalize(),
            'name': member.get_full_name() or member.username,
            'is_active': member.is_active,
        })
    return JsonResponse({'members': data})

@login_required
def remove_member(request):
    """Remove a member from the organization."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    user = request.user
    if not user.organization:
        return JsonResponse({'error': 'You are not associated with an organization.'}, status=400)

    # Only the first user (org admin) can remove members
    first_user = User.objects.filter(organization=user.organization).order_by('date_joined').first()
    if first_user != user:
        return JsonResponse({'error': 'Only the organization admin can remove members.'}, status=403)

    member_id = request.POST.get('member_id')
    if not member_id:
        return JsonResponse({'error': 'Member ID is required.'}, status=400)

    try:
        member = User.objects.get(id=member_id, organization=user.organization)
        
        # Prevent removing yourself
        if member == user:
            return JsonResponse({'error': 'You cannot remove yourself. Use account deletion in profile settings instead.'}, status=400)
        
        # Check if this is the last admin
        admin_count = User.objects.filter(organization=user.organization, is_active=True).count()
        is_last_admin = (member == first_user and admin_count <= 1)
        
        if is_last_admin:
            return JsonResponse({'error': 'Cannot remove the last admin. Please assign another admin first.'}, status=400)
        
        username = member.username
        member.delete()
        return JsonResponse({'success': True, 'message': f'Member {username} has been removed.'})
            
    except User.DoesNotExist:
        return JsonResponse({'error': 'Member not found.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def pending_invites(request):
    """Return list of pending invitations"""
    user = request.user
    if not user.organization:
        return JsonResponse({'invites': []})
    invites = Invitation.objects.filter(organization=user.organization, status='sent')
    data = []
    for inv in invites:
        data.append({
            'id': inv.invitation_id,
            'email': inv.recipient_email,  # decrypted automatically
            'role': inv.recipient_role,
            'created_at': inv.created_at.isoformat(),
        })
    return JsonResponse({'invites': data})

@login_required
def send_invitation(request):
    """Send invitation email to new team member"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    user = request.user
    if not user.organization:
        return JsonResponse({'error': 'You are not associated with an organization.'}, status=400)

    # Only the first user (org admin) can invite
    first_user = User.objects.filter(organization=user.organization).order_by('date_joined').first()
    if first_user != user:
        return JsonResponse({'error': 'Only the organization admin can send invitations.'}, status=403)

    email = request.POST.get('email')
    role = request.POST.get('role')
    if not email or not role:
        return JsonResponse({'error': 'Email and role are required.'}, status=400)

    if role not in ['observer', 'tester']:
        return JsonResponse({'error': 'Invalid role.'}, status=400)

    try:
        token = uuid.uuid4()
        invitation = Invitation.objects.create(
            sender=user,
            organization=user.organization,
            recipient_email=email,
            token=token,
            recipient_role=role,
            status='sent'
        )

        # Send invitation email
        domain = request.get_host()
        protocol = 'https' if request.is_secure() else 'http'
        invite_link = f"{protocol}://{domain}/accounts/invite/{token}/"

        send_email_by_type('invite', email, {
            "inviter_name": f"{user.first_name} {user.last_name}",
            "inviter_role": "Organization Admin",
            "inviter_company": user.organization.org_name,
            "company": user.organization.org_name,
            "role": role,
            "invite_link": invite_link,
        })

        return JsonResponse({'success': True, 'message': f'Invitation sent to {email}'})
    except Exception as e:
        print(f"Error sending invitation: {e}")
        traceback.print_exc()
        return JsonResponse({'error': f'Failed to send invitation: {str(e)}'}, status=500)

@login_required
def resend_invitation(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    invite_id = request.POST.get('invite_id')
    try:
        inv = Invitation.objects.get(invitation_id=invite_id, organization=request.user.organization, status='sent')
        domain = request.get_host()
        protocol = 'https' if request.is_secure() else 'http'
        invite_link = f"{protocol}://{domain}/accounts/invite/{inv.token}/"
        send_email_by_type('invite', inv.recipient_email, {
            "inviter_name": f"{inv.sender.first_name} {inv.sender.last_name}",
            "inviter_role": "Organization Admin",
            "inviter_company": inv.organization.org_name,
            "company": inv.organization.org_name,
            "role": inv.recipient_role,
            "invite_link": invite_link,
        })
        return JsonResponse({'success': True})
    except Invitation.DoesNotExist:
        return JsonResponse({'error': 'Invitation not found'}, status=404)
    except Exception as e:
        print(f"Error resending invitation: {e}")
        traceback.print_exc()
        return JsonResponse({'error': f'Failed to resend invitation: {str(e)}'}, status=500)

@login_required
def cancel_invitation(request):
    """Cancel a pending invitation"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    invite_id = request.POST.get('invite_id')
    try:
        inv = Invitation.objects.get(invitation_id=invite_id, organization=request.user.organization, status='sent')
        inv.delete()
        return JsonResponse({'success': True})
    except Invitation.DoesNotExist:
        return JsonResponse({'error': 'Invitation not found'}, status=404)

def accept_invitation(request, token):
    """Handle user registration via invitation link"""
    invitation = get_object_or_404(Invitation, token=token, status='sent')
    # Optional expiration check (7 days)
    if invitation.created_at < timezone.now() - timezone.timedelta(days=7):
        messages.error(request, 'This invitation has expired.')
        return redirect('public_register')

    if request.method == 'POST':
        form = InvitationSignupForm(request.POST, email=invitation.recipient_email)
        if form.is_valid():
            user = form.save(commit=False)
            user.organization = invitation.organization
            user.is_active = False
            user.save()

            # Update invitation
            invitation.recipient_user = user
            invitation.status = 'awaiting_approval'
            invitation.save()

            # Store in session
            request.session['pending_company'] = invitation.organization.org_name
            request.session['pending_email'] = user.email
            request.session['pending_submitted'] = timezone.now().isoformat()

            # Send confirmation to user
            send_email_by_type('registration', user.email, {"username": user.username})

            # Generate approval URLs
            domain = request.get_host()
            protocol = 'https' if request.is_secure() else 'http'
            approve_url = f"{protocol}://{domain}/api/admin/approve/{user.id}/"
            reject_url = f"{protocol}://{domain}/api/admin/reject/{user.id}/"

            # Notify organization admin
            org_admin = User.objects.filter(organization=invitation.organization).order_by('date_joined').first()
            if org_admin:
                send_email_by_type('request', org_admin.email, {
                    'requester_name': f"{user.first_name} {user.last_name}",
                    'requester_email': user.email,
                    'company': invitation.organization.org_name,
                    'role': invitation.recipient_role,
                    'approve_url': approve_url,
                    'reject_url': reject_url,
                })

            messages.success(request, 'Account created successfully! Please wait for admin approval.')
            return redirect('accounts:waiting')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = InvitationSignupForm(email=invitation.recipient_email)

    context = {
        'form': form,
        'email': invitation.recipient_email,
        'organization': invitation.organization.org_name,
    }
    return render(request, 'registration/invite_signup.html', context)

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