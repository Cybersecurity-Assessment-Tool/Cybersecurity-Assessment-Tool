# accounts/views.py
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

    class SignUpView(CreateView):
        form_class = UserCreationForm
        success_url = reverse_lazy("login")
        template_name = "registration/registration_dummy.html"

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        form._meta.model = Invitation
        return form
    
    def form_valid(self, form):
        # Create user (don't save yet)
        invitation = form.save(commit=False)
        invitation.is_active = False  # ← Pending OTP verification
        invitation.save()
        
        # Store user data + send OTP
        # PASS the actual form data to session
        self.request.session['pending_user_id'] = invitation.id
        self.request.session['registration_data'] = {
            'username': form.cleaned_data['username'],
            'email': form.cleaned_data['email'],
            'password': form.cleaned_data['password1']  # password1 from UserCreationForm
        }
        
        send_otp_view(self.request, invitation.recipient_email)  # This will send OTP and store registration data in session
        
        #registration_view(self.request)  # This will send OTP and store registration data in session
        return redirect('otp_verify')
