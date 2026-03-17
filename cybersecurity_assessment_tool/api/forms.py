from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from api.models import User, Organization, Invitation
import random

#User = get_user_model()

class PublicRegistrationForm(UserCreationForm):
    first_name = forms.CharField(max_length=100, required=True)
    last_name = forms.CharField(max_length=100, required=True)
    company = forms.CharField(max_length=100, required=True)
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'first_name', 'last_name', 'company']

    def clean_company(self):
        company = self.cleaned_data.get('company', '').strip()
        if Organization.objects.filter(org_name__iexact=company).exists():
            raise forms.ValidationError('This company is already registered. Please contact your organization administrator or use a different company name.')
        return company

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_active = False
        user.email = self.cleaned_data.get('email', '')
        user.first_name = self.cleaned_data.get('first_name', '')
        user.last_name = self.cleaned_data.get('last_name', '')

        # Properly hash password
        user.password=self.cleaned_data.get('password1')

        # Get or create organization safely
        org_name = self.cleaned_data.get('company', '')
        if org_name:
            organization, _ = Organization.objects.get_or_create(org_name=org_name)
            user.organization = organization

        if commit:
            user.save()
        return user
    
ROLE_CHOICES = [
    ('observer', 'Observer'),
    ('tester', 'Tester'),
]

class InviteUserForm(forms.Form):
    # Sender info (for testing email context)
    '''
    sender_name = forms.CharField(
        label="Your Name", 
        initial="Casey Rivera",
        help_text="Name that appears in invitation email"
    )
    sender_email = forms.EmailField(
        label="Your Email", 
        initial="cyberassessmenttool@gmail.com",
        help_text="Sender email for testing"
    )
    '''
    
    # Recipient info
    first_name = forms.CharField(max_length=50, label="Recipient First Name")
    last_name = forms.CharField(max_length=50, label="Recipient Last Name") 
    #username = forms.CharField(max_length=150, label="Recipient Username")
    company = forms.CharField(max_length=200, label="Recipient Company")
    email = forms.EmailField(label="Recipient Work Email")
    role = forms.ChoiceField(
        choices=[
            ('tester', 'Tester'),
            ('observer', 'Observer'),
        ],
        label="Recipient Role",
        initial='Org Admin',
        help_text="Role the invited user will have"
    )
    
    '''
    # Password fields
    password = forms.CharField(
        widget=forms.PasswordInput, 
        label="Temporary Password",
        initial="EmptyPassword"
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput, 
        label="Confirm Password",
        initial="EmptyPasword"
    )
    '''
    
    def clean(self):
        cleaned_data = super().clean()
        #password = cleaned_data.get("password")
        #confirm_password = cleaned_data.get("confirm_password")
        
        #if password and confirm_password and password != confirm_password:
            #raise forms.ValidationError("Passwords don't match")
        return cleaned_data
    
    def save(self, commit=True):
        cleaned_data = self.cleaned_data
        
        organization, created = Organization.objects.get_or_create(
        org_name=cleaned_data['company'])
        
        invitation = Invitation.objects.create(
            first_name=cleaned_data.get('first_name'),
            last_name=cleaned_data.get('last_name'),
            email=cleaned_data.get('email'),
            organization=organization,
            recipient_role=cleaned_data.get('role')
        )
        
        if commit:
            invitation.save()
        return invitation
 

