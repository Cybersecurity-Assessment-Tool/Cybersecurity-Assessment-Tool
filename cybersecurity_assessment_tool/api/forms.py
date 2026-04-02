from django import forms
    
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

