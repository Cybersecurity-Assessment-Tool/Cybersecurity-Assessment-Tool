import uuid
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from api.utils.email_factory import send_email_by_type  # ← NEW IMPORT
import time
from api.forms import PublicRegistrationForm
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Invitation, Organization, User, Report, Risk
from .serializers import OrganizationSerializer, UserSerializer, ReportSerializer, RiskSerializer
from django.contrib.auth import get_user_model

User = get_user_model()


# Simple session-based OTP storage (use Redis/Cache in production)
def otp_verify_view(request, token=False):
    if request.method == 'POST':
        print("=== DEBUG INFO ===")
        print(f"POST data: {request.POST}")  # See ALL form data
        
        # Get OTP from all 6 inputs
        otp_input = ''.join([
            request.POST.get(f'otp{i}', '') for i in range(1, 7)
        ]).strip()
        
        #print(f"User entered OTP: '{otp_input}'")  # What user typed
        #print(f"Stored OTP: '{request.session.get('otp_code')}'")  # What we expect
        
        stored_otp = request.session.get('otp_code')
        otp_created = request.session.get('otp_created')
        
        #print(f"OTP created time: {otp_created}")
        #print(f"Current time: {time.time()}")
        #print(f"Time diff: {time.time() - otp_created if otp_created else 'N/A'}")
        
        # Check if OTP expired (5 minutes)
        if not stored_otp or not otp_created or (time.time() - otp_created > 300):
            messages.error(request, 'OTP expired or not found. Please request a new one.')
            return render(request, 'otp_verify.html')
        
        if otp_input == stored_otp:
                # Login user
                #auth.login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
    
    return render(request, 'otp_verify')

def send_otp_view(request, recipient):
    """Send OTP to user using email_factory"""
    # Get from form/session in production
    recipient =  recipient or "onellamoitra@gmail.com"
    
    # Send OTP using your new factory (handles generation + sending)
    context = send_email_by_type('otp', recipient)
    otp = context['otp']  # Extract from returned context
    
    print(f"Generated OTP: {otp}")  # For debugging, remove in production
    
    # Store in session
    request.session['otp_code'] = otp
    request.session['otp_created'] = time.time()
    
    messages.success(request, 'OTP sent to your email!')
    return redirect('otp_verify') 

def send_invite_mail(request, recipient_email):
    token = str(uuid.uuid4())  # Generate a unique token for the invite link
    
    invitation = Invitation.objects.create(
            sender=request.user,
            recipient_email=recipient_email,
            token=token,
            recipient_role=request.get('recipient_role', 'observer'),  # Default to 'observer' if not provided
            status='sent',
        )
    domain = request.get_host()
        
    send_email_by_type('invite', recipient_email, {
        "inviter_name": invitation.sender.username,
        "inviter_role": invitation.sender.group.help_text,
        "inviter_company": invitation.sender.organization.org_name,
        "company": invitation.sender.organization.org_name,
        "role": invitation.recipient_role,
        "invite_link": f"http://{domain}/invite/{token}/",
    })
        
def register_user_invite(request, invitation):
    if request.method == 'POST':
        user = form.save(commit=False)
        user.is_active = False  # ← Pending OTP verification
        user.object.create(
            id = request.session.get('pending_user_id'),
            username = request.session['registration_data']['username'],
        )
            
        send_email_by_type('registration', invitation.recipient_email, {
            "username": user.username
        })
        send_email_by_type('request', invitation.sender.email, {
            "requester_name": user.username,
            "requester_email": user.email,
            "company": invitation.sender.organization.org_name,
            "role": invitation.recipient_role
        })

# Takes care of public registration for Org Admins and company databases         
def public_registration(request):
    
    #Automatic invite token generated
    token = str(uuid.uuid4())
    if request.method == 'POST':
        # Taking from form to handle public registration with company field and automatic invite creation (Found in forms.py))
        form = PublicRegistrationForm(request.POST)
        form._meta.model = User
        
        # Debug Info
        # print("POST data:", request.POST)           # What was submitted
        # print("Form errors:", form.errors)          # What failed validation
        # print("Form is valid:", form.is_valid())    # Should be True
        
        #Checking all requirements for public registration form
        if form.is_valid(): 
            # Doesn't save user until we call form.save(), which allows us to set additional fields before saving to DB
            user = form.save(commit=False)
            # Keeps user from accessing account until admin approval, also ensures they verify email
            user.is_active = False
            #Initialize user with form data, but we will override some fields to ensure data integrity and proper relationships
            user.first_name = request.POST.get('first_name')
            user.last_name = request.POST.get('last_name')
            user.email = request.POST.get('email')
            user.password = request.POST.get('password1')
            
            # Associate user with organization (get or create based on company name)
            org_name = form.cleaned_data.get('company')
            if org_name:
                org, _ = Organization.objects.get_or_create(org_name=org_name)
                user.organization = org

            user.save()
            
            '''
            system_user, _ = User.objects.get_or_create(
                first_name="System",
                last_name="Admin",
                username="Cybersecurity Assessment Tool",
                defaults={"is_active": False, "email": "cyberassessmenttool@gmail.com", "password": "N/A"}
            )
            '''
            
            # Our information email that receives the registration request and "sends" the invite
            system_user = User.objects.get(username="Cybersecurity Assessment Tool")
            system_user.email = "cyberassessmenttool@gmail.com"

            # Creates invitation for the new user with status "sent" (pending approval) and default role of "Org Admin" 
            Invitation.objects.create(
                sender=system_user,
                recipient_email=user.email,
                token=str(uuid.uuid4()),
                recipient_role="Org Admin",
                status="sent",
                organization=user.organization
            )
            
            # print("After Save")

            # Sends email to the new user confirming their registration request
            send_email_by_type('registration', user.email, {
                "username": user.username
            })
            
            # Sends email to the system admin (or real admin in production) with the details of the new registration and a link to approve/reject
            send_email_by_type('request', system_user.email, {
                'requester_name': f"{user.first_name} {user.last_name}",
                "requester_email": user.email,
                "company": request.POST.get('company', 'N/A'),
                "role": "Org Admin",
                "override_context": True,
            })
        
            return render(request, 'public_registration.html')
        else:
            # print("Here")
            form = PublicRegistrationForm()
    
    return render(request, 'public_registration.html')

class OrganizationViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing Organization instances.
    Requires authentication to modify data.
    """
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [IsAuthenticated]


class UserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing User instances.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
   
    def get_permissions(self):
        if self.action == 'create':
            return [AllowAny()]
        return [IsAuthenticated()]


class ReportViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing Report instances.
    Automatically filters reports to the current user's organization (optional security measure).
    """
    serializer_class = ReportSerializer
    permission_classes = [IsAuthenticated]
    
    # restrict reports to the user's organization for basic data separation
    def get_queryset(self):
        # Only show reports belonging to the user's organization
        return Report.objects.filter(organization=self.request.user.organization).order_by('-started')
        
    # automatically set the user_created and organization fields on creation
    def perform_create(self, serializer):
        serializer.save(user_created=self.request.user, organization=self.request.user.organization)


class RiskViewSet(viewsets.ModelViewSet):
    """
    ViewSet for viewing and editing Risk instances.
    """
    queryset = Risk.objects.all()
    serializer_class = RiskSerializer
    permission_classes = [IsAuthenticated]
    
    # will restrict this further (only show risks related to reports the user can access)
    # for now, it shows all risks



# TEST below
from django.shortcuts import get_object_or_404

def home(request):
    """Display home page"""
    context = {
        'page_title': 'LogoSoon',
        'description': 'Cybersecurity assessment tool',
    }
    return render(request, 'home.html', context)

def dashboard(request):
    """Display dashboard page"""
    return render(request, 'dashboard.html')

def report_list(request):
    """Display list of reports"""
    reports = Report.objects.all()
    
    context = {
        'reports': reports,
        'total_count': reports.count()
    }
    return render(request, 'report_list.html', context)

# def report_detail(request, id):
#     """Display single report (not implemented yet)"""
#     report = get_object_or_404(Report, id=id)
    
#     context = {
#         'report': report
#     }
#     return render(request, 'reports/report_detail.html', context)

def settings(request):
    """Display settings page"""
    return render(request, 'settings.html')

def profile(request):
    """Display profile page"""
    return render(request, 'profile.html')
