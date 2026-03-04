from django import forms
from django.contrib.auth import get_user_model
from .models import UserProfile

User = get_user_model()

class UserProfileForm(forms.ModelForm):
    """
    Form for editing user profile information.
    Includes save indicators and validation.
    """
    class Meta:
        model = UserProfile
        fields = ['display_name', 'profile_image','default_view']
        widgets = {
            'display_name': forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Enter your display name'}),
            'default_view': forms.Select(attrs={'class': 'form-select'}),
            'profile_image': forms.FileInput(attrs={'class': 'form-file', 'accept': 'image/*'}),
        }
        # 'display_name', 'profile_image', 'job_title', 'phone_number', 'timezone', 'email_notifications', 'email_on_critical', 'email_on_scan_complete', 'email_digest', 'items_per_page', 'default_view'

        # 'job_title': forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'e.g., Security Analyst'}),
        # 'phone_number': forms.TextInput(attrs={'class': 'form-input', 'placeholder': '+1 (555) 123-4567'}),
        # 'timezone': forms.Select(attrs={'class': 'form-select'}),
        # 'email_digest': forms.Select(attrs={'class': 'form-select'}),
        # 'items_per_page': forms.Select(attrs={'class': 'form-select'}),
    
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
        email = self.cleaned_data['email']
        if User.objects.exclude(pk=self.instance.pk).filter(email=email).exists():
            raise forms.ValidationError('This email is already in use.')
        return email

class TwoFactorSetupForm(forms.Form):
    """
    Placeholder form for 2FA setup.
    TO DO: Implement actual 2FA using django-otp or similar
    """
    verification_code = forms.CharField(
        max_length=6,
        min_length=6,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'placeholder': 'Enter 6-digit code',
            'pattern': '[0-9]{6}'
        })
    )
    
    def clean_verification_code(self):
        code = self.cleaned_data.get('verification_code')
        if code and not code.isdigit():
            raise forms.ValidationError('Code must contain only numbers')
        return code