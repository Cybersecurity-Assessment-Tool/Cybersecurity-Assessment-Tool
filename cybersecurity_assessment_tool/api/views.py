import uuid
from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from api.utils.email_factory import send_email_by_type  # ← NEW IMPORT
import time
from api.forms import PublicRegistrationForm, InviteUserForm
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Invitation, Organization, User, Report, Risk
from .serializers import OrganizationSerializer, UserSerializer, ReportSerializer, RiskSerializer
from django.contrib.auth import get_user_model
from django.urls import reverse
from urllib.parse import quote

User = get_user_model()

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
        
            return render(request, 'registration/public_registration.html')
        else:
            # print("Here")
            form = PublicRegistrationForm()
    
    return render(request, 'registration/public_registration.html')


def process_invite_user_form(request):
    print("🔥 1. VIEW STARTED")
    
    if request.method == 'POST':
        print("🔥 2. POST REQUEST")
        form = InviteUserForm(request.POST)
        
        if form.is_valid():
            print("🔥 4. FORM VALID - cleaned_data:", form.cleaned_data)
            
            # 1. Find or create organization
            organization, created = Organization.objects.get_or_create(
                org_name=form.cleaned_data['company'],
                defaults={'organization_id': uuid.uuid4()}
            )
            # print(f"✅ Org: {organization.org_name}")
            
            # 2. Create temp_sender  
            temp_sender, _ = User.objects.get_or_create(
                username="temp_sender",
                defaults={
                    'first_name': 'System', 
                    'last_name': 'Sender',
                    'email': 'cyberassessmenttool@gmail.com',
                    'is_active': False
                }
            )
            
            # 3. Create INVITATION ONLY (no user created)
            token = str(uuid.uuid4())
            invitation = Invitation.objects.create(
                sender=temp_sender,
                organization=organization,
                recipient_email=form.cleaned_data['email'],
                recipient_role=form.cleaned_data['role'],
                token=token,
                status='sent'
            )
            
            # 4. 👇 STORE IN SESSION (key part!)
            request.session['invite_data'] = {
                'token': token,
                'first_name': form.cleaned_data['first_name'],
                'last_name': form.cleaned_data['last_name'],
                'full_name': f"{form.cleaned_data['first_name']} {form.cleaned_data['last_name']}",
                'email': form.cleaned_data['email'],
                'company': organization.org_name,
                'role': form.cleaned_data['role'],
            }
            
            # 5. Send email
            invite_url = request.build_absolute_uri(f"/accounts/invite/{token}/accept/")
            email_context = {
                "inviter_name": form.cleaned_data['sender_name'],
                "company": organization.org_name,
                "role": invitation.get_recipient_role_display(),
                "invite_link": invite_url, 
            }
            send_email_by_type('invite', form.cleaned_data['email'], email_context)
            
            messages.success(request, 'Invite sent!')
            return redirect('home')
    
    return render(request, 'invite_user.html', {'form': InviteUserForm()})


def invite_accept(request, token):
    """User clicks email link → redirects to signup with token"""
    try:
        invitation = Invitation.objects.get(token=token, status='sent')
        # Redirect to signup page with token in URL
        signup_url = reverse('accounts:invite_signup', kwargs={'token': token})
        return redirect(signup_url)
    except Invitation.DoesNotExist:
        return redirect('invite_expired')

def validate_invite(request, token):
    print(f"🔍 validate_invite called with token: '{token}'")  # FIRST LINE
    
    # Debug all invitations
    # all_invitations = list(Invitation.objects.values('token', 'status', 'recipient_email')[:5])
    # print(f"🔍 Found {Invitation.objects.count()} total invitations")
    # print(f"🔍 Sample: {all_invitations}")
    
    try:
        invitation = Invitation.objects.get(token=token, status="Awaiting Approval")
        print(f"✅ Invitation found: {invitation.recipient_email}")
    except Invitation.DoesNotExist:
        print(f"❌ NO INVITATION with token='{token}' AND status='Awaiting Approval'")
        print(f"❌ Invitations with that token: {list(Invitation.objects.filter(token=token).values('status'))}")
        messages.error(request, "Invalid or expired invitation.")
        return redirect('home')
    
    print(f"Recipient Email: {invitation.recipient_email}\nRecipient Organization: {invitation.organization}")
    
    # Rest of your code...
    user = User.objects.get(email=invitation.recipient_email, organization=invitation.organization)
    print(f"✅ User found: {user.username}")
    
    # Activate user + approve invitation
    user.is_active = True
    user.save(update_fields=['is_active'])
    
    invitation.status = "Approved"
    invitation.save(update_fields=['status'])

    
    # Notify USER they are approved
    domain = request.get_host()
    login_url = f"http://{domain}/accounts/login"
    
    print(f"Recipient email: {user.email}")

    send_email_by_type('approval', user.email, {
        "username": user.username,
        "login_url": login_url,  # Dynamic full URL!
        "org_name": invitation.organization.org_name,
    })
    
    messages.success(request, f"✅ {user.username} activated! Approval email sent.")
    
    return redirect('home')
    
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
