from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from api.models import User, Organization, generate_email_hash
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

User = get_user_model()


class UserProfileForm(forms.ModelForm):
    """
    Form for editing user profile information.
    Includes save indicators and validation.
    """
    class Meta:
        model = User
        fields = ['username', 'profile_image']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Enter your display name'}),
            'profile_image': forms.FileInput(attrs={'class': 'form-file', 'accept': 'image/*'}),
        }
        # 'display_name', 'profile_image', 'job_title', 'phone_number', 'timezone', 'email_notifications', 'email_on_critical', 'email_on_scan_complete', 'email_digest', 'items_per_page', 'default_view'

        # 'job_title': forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g., Security Analyst'}),
        # 'phone_number': forms.TextInput(attrs={'class': 'form-input', 'placeholder': '+1 (555) 123-4567'}),
        # 'timezone': forms.Select(attrs={'class': 'form-select'}),
        # 'email_digest': forms.Select(attrs={'class': 'form-select'}),
        # 'items_per_page': forms.Select(attrs={'class': 'form-select'}),
        # 'default_view': forms.Select(attrs={'class': 'form-select'}),
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add Bootstrap classes to checkboxes
        # self.fields['email_notifications'].widget.attrs.update({'class': 'form-checkbox'})
        # self.fields['email_on_critical'].widget.attrs.update({'class': 'form-checkbox'})
        # self.fields['email_on_scan_complete'].widget.attrs.update({'class': 'form-checkbox'})

class UserEmailForm(forms.ModelForm):
    """Form for changing user email address"""
    class Meta:
        model = User
        fields = ['email']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-input', 'placeholder': 'your@email.com'})
        }
    
    def clean_email(self):
        email = self.cleaned_data.get('email')
        
        if email:
            # 1. Generate the hash of the input email
            email_hash = generate_email_hash(email)
            
            # 2. Check if this hash exists, excluding the current user's own hash
            if User.objects.exclude(pk=self.instance.pk).filter(email_hash=email_hash).exists():
                raise forms.ValidationError('This email is already in use.')
                
        return email

# class TwoFactorSetupForm(forms.Form):
#     """
#     Placeholder form for 2FA setup.
#     TO DO: Implement actual 2FA using django-otp or similar
#     """
#     verification_code = forms.CharField(
#         max_length=6,
#         min_length=6,
#         required=False,
#         widget=forms.TextInput(attrs={
#             'class': 'form-input',
#             'placeholder': 'Enter 6-digit code',
#             'pattern': '[0-9]{6}'
#         })
#     )
    
#     def clean_verification_code(self):
#         code = self.cleaned_data.get('verification_code')
#         if code and not code.isdigit():
#             raise forms.ValidationError('Code must contain only numbers')
#         return code
    
class CustomUserCreationForm(UserCreationForm):
    """
    Custom signup form that requires email and adds basic styling.
    """
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-input',
            'placeholder': 'your@email.com'
        })
    )
    
    class Meta(UserCreationForm.Meta):
        model = User  # This uses your custom User model from api.models
        fields = ('username', 'email', 'password1', 'password2')
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add CSS classes and placeholders to all fields
        for field_name in self.fields:
            self.fields[field_name].widget.attrs.update({
                'class': 'form-input',
                'placeholder': self.fields[field_name].label or field_name
            })
        
        # Customize specific fields
        self.fields['username'].widget.attrs.update({
            'placeholder': 'Choose a username'
        })
        self.fields['password1'].widget.attrs.update({
            'placeholder': 'Create a password'
        })
        self.fields['password2'].widget.attrs.update({
            'placeholder': 'Confirm your password'
        })
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user

class PublicRegistrationForm(UserCreationForm):
    first_name = forms.CharField(max_length=100, required=True)
    last_name = forms.CharField(max_length=100, required=True)
    company = forms.CharField(max_length=100, required=True)
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name', 'company', 'password1', 'password2']

    def __init__(self, *args, require_password=True, **kwargs):
        self.require_password = require_password
        super().__init__(*args, **kwargs)

        if not self.require_password:
            self.fields['password1'].required = False
            self.fields['password2'].required = False
            self.fields['password1'].help_text = 'Optional when you continue with Google or Microsoft.'
            self.fields['password2'].help_text = 'Optional when you continue with Google or Microsoft.'

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if email:
            email_hash = generate_email_hash(email)
            if User.objects.filter(email_hash=email_hash).exists():
                raise forms.ValidationError('An account with this email already exists.')
        return email

    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        if not password:
            return None if not self.require_password else password

        try:
            validate_password(password)
        except ValidationError as e:
            raise forms.ValidationError(e.messages)
        return password

    def clean(self):
        cleaned_data = super().clean()
        
        # Move password strength errors from password1 to password2
        if 'password1' in self.errors:
            # Capture the errors from password1
            p1_errors = self.errors.pop('password1')
            for error in p1_errors:
                self.add_error('password2', error)
        
        # Then check password match
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if self.require_password and not password1:
            self.add_error('password1', 'Password is required unless you continue with Google or Microsoft.')
        if self.require_password and not password2:
            self.add_error('password2', 'Please confirm your password unless you continue with Google or Microsoft.')
        if password1 and password2 and password1 != password2:
            self.add_error('password2', "The two password fields didn't match.")
        
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_active = False
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']

        if not self.cleaned_data.get('password1'):
            user.set_unusable_password()

        org_name = self.cleaned_data.get('company', '')
        if org_name:
            organization, _ = Organization.objects.get_or_create(org_name=org_name)
            user.organization = organization

        if commit:
            user.save()
        return user

class InvitationSignupForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        self.email = kwargs.pop('email', None)
        self.require_password = kwargs.pop('require_password', True)
        super().__init__(*args, **kwargs)

        if not self.require_password:
            self.fields['password1'].required = False
            self.fields['password2'].required = False
            self.fields['password1'].help_text = 'Optional when you continue with Google or Microsoft.'
            self.fields['password2'].help_text = 'Optional when you continue with Google or Microsoft.'

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if self.require_password and not password1:
            self.add_error('password1', 'Password is required unless you continue with Google or Microsoft.')
        if self.require_password and not password2:
            self.add_error('password2', 'Please confirm your password unless you continue with Google or Microsoft.')

        # If passwords don't match, force the error onto the 'password2' line
        # instead of letting it default to the top of the box.
        if password1 and password2 and password1 != password2:
            self.add_error('password2', "The two password fields didn't match.")

        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.email
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        if not self.cleaned_data.get('password1'):
            user.set_unusable_password()
        if commit:
            user.save()
        return user
    
from django.contrib.auth.forms import PasswordResetForm
from django.template.loader import render_to_string
from django_q.tasks import async_task
from django.contrib.auth import get_user_model
from api.models import generate_email_hash  # Adjust this import if needed

User = get_user_model()

class AsyncPasswordResetForm(PasswordResetForm):
    
    def get_users(self, email):
        """
        Override how Django finds the user to account for encrypted emails!
        """
        # 1. Hash the typed email so it matches the DB
        email_hash = generate_email_hash(email)
        
        # 2. Find active users with that exact hash
        active_users = User.objects.filter(email_hash=email_hash, is_active=True)
        
        # 3. Yield them back to Django (only if they have a real password)
        for user in active_users:
            if user.has_usable_password():
                yield user

    def send_mail(self, subject_template_name, email_template_name,
                  context, from_email, to_email, html_email_template_name=None):
        """
        Send the email via Django Q2 Background Worker
        """
        subject = render_to_string(subject_template_name, context)
        subject = ''.join(subject.splitlines())
        
        body = render_to_string(email_template_name, context)
        
        html_body = None
        if html_email_template_name:
            html_body = render_to_string(html_email_template_name, context)

        async_task(
            'django.core.mail.send_mail',
            subject,
            body,
            from_email,
            [to_email],
            fail_silently=False,
            html_message=html_body,
        )