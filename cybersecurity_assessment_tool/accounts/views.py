from pyexpat.errors import messages

from django.urls import reverse, reverse_lazy
from django.views.generic import CreateView
from api.models import Invitation, User
from .forms import CustomUserCreationForm
from django.contrib.auth import login
from django.shortcuts import get_object_or_404, redirect
from api.utils.email_factory import send_email_by_type

class SignUpView(CreateView):
    form_class = CustomUserCreationForm
    template_name = "registration/signup.html"
    success_url = reverse_lazy("login")  # fallback if no token

    def dispatch(self, request, *args, **kwargs):
        # Locating invitation through token
        self.invitation = None
        token = kwargs.get('token')
        if token:
            self.invitation = get_object_or_404(
                Invitation, token=token, status='sent'
            )
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        
        # 👇 INCORPORATE SESSION DATA INTO FORM
        invite_data = self.request.session.get('invite_data', {})
        if self.invitation and invite_data.get('token') == self.invitation.token:
            kwargs['initial'] = invite_data
        elif self.invitation:
            # Fallback initial data
            email_prefix = self.invitation.recipient_email.split('@')[0].title()
            kwargs['initial'] = {
                'first_name': email_prefix.split()[0] if ' ' in email_prefix else email_prefix,
                'last_name': email_prefix.split()[-1] if ' ' in email_prefix else '',
                'email': self.invitation.recipient_email,
            }
        
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Still pass user_context for display
        invite_data = self.request.session.get('invite_data', {})
        if self.invitation:
            if invite_data.get('token') == self.invitation.token:
                context["user_context"] = invite_data
            else:
                context["user_context"] = {
                    "first_name": self.request.session.get('invite_data', {}).get('first_name', ''),
                    "last_name": self.request.session.get('invite_data', {}).get('last_name', ''),
                    "full_name": f"{self.request.session.get('invite_data', {}).get('first_name', '')} {self.request.session.get('invite_data', {}).get('last_name', '')}".strip(),
                    "company": getattr(self.invitation.organization, 'org_name', 'N/A'),
                    "role": self.invitation.get_recipient_role_display(),
                    "email": self.invitation.recipient_email,
                }
        return context

    def form_valid(self, form):
        if self.invitation:
            invite_data = self.request.session.get('invite_data', {})
            print("🔍 form_valid START")
            
            invitation = self.invitation
            
            # Extract data
            first_name = invite_data['first_name']
            last_name = invite_data['last_name']
            email = invitation.recipient_email
            organization = invitation.organization
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            
            print(f"🔍 Creating user: {username} / {email}")
            
            # CREATE USER with explicit save
            new_user = User.objects.create(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                organization=organization,
                password=password,
                is_active=False,
            )
            
            print(f"🔍 User object ID before refresh: {new_user.id}")
            
            # FORCE REFRESH FROM DB
            new_user.refresh_from_db()
            print(f"✅ User SAVED ID: {new_user.id}")
            
            # Verify in DB immediately
            db_user = User.objects.filter(id=new_user.id).first()
            print(f"✅ DB CONFIRM: {bool(db_user)}")
            
            # Update invitation
            invitation.status = "Awaiting Approval"
            invitation.recipient_user = new_user
            invitation.save()
            print(f"✅ Invitation updated: {invitation.status}")
            
            # Clean session
            if 'invite_data' in self.request.session:
                del self.request.session['invite_data']
            
            # SAFE email sending
            try:
                send_email_by_type('registration', new_user.email)
                print("✅ Registration email sent")
            except Exception as e:
                print(f"⚠️ Registration email failed: {e}")
            
            try:
                approve_url = self.request.build_absolute_uri(f"/accounts/admin/approve/{invitation.token}/")
                send_email_by_type('request', invitation.sender.email, {
                    "requester_name": f"{new_user.first_name} {new_user.last_name}",
                    "requester_email": new_user.email,
                    "company": new_user.organization.org_name,
                    "role": invitation.recipient_role,
                    "approve_url": approve_url,
                })
                print("✅ Admin request email sent")
            except Exception as e:
                print(f"⚠️ Admin email failed: {e}")
            
            # CRITICAL: Use self.request for messages
            # messages.success(self.request, f"✅ Registration request sent for {new_user.email}")
            
            print("🔍 form_valid COMPLETE")
            return redirect('home')
        
        return super().form_valid(form)


            
            
        
### Test
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

class UserDetailView(LoginRequiredMixin, TemplateView):
    template_name = "accounts/user_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user
        return context
    
from django.shortcuts import get_object_or_404, redirect, render
    
def settings(request):
    """Display settings page"""
    return render(request, 'accounts/settings.html')

def upload_profile_image(request):
    """Display upload profile image page"""
    return render(request, 'accounts/upload_profile_image.html')

def organization(request):
    """Display organization page"""
    return render(request, 'accounts/organization.html')
    
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