from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from api.models import User, Organization

#User = get_user_model()

class PublicRegistrationForm(UserCreationForm):
    first_name = forms.CharField(max_length=100, required=True)
    last_name = forms.CharField(max_length=100, required=True)
    company = forms.CharField(max_length=100, required=True)
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2', 'first_name', 'last_name', 'company']

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

class SendInviteForm(forms.Form):
    sender_first_name = forms.CharField(max_length=50)
    sender_last_name = forms.CharField(max_length=50)
    sender_email = forms.EmailField()
    sender_company = forms.CharField(max_length=100)
    sender_role = forms.CharField(max_length=50)

    recipient_email = forms.EmailField()
    recipient_role = forms.ChoiceField(choices=ROLE_CHOICES)

