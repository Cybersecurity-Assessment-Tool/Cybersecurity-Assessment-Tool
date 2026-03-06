from django.contrib.auth.forms import UserCreationForm
from django.urls import reverse_lazy
from django.views.generic import CreateView
from api.models import User

class SignUpView(CreateView):
    form_class = UserCreationForm
    success_url = reverse_lazy("login")
    template_name = "registration/signup.html"

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        form._meta.model = User
        return form

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