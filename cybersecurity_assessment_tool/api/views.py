from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from api.utils.email_factory import send_email_by_type  # ← NEW IMPORT
import time

# Simple session-based OTP storage (use Redis/Cache in production)
def otp_verify_view(request, signup=False):
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
            pending_user_id = request.session.get('pending_user_id')
            registration_data = request.session.pop('registration_data', None)
            
            if pending_user_id and registration_data:
                # Activate user + send welcome email
                #user = Invitation.objects.get(id=pending_user_id)
                #user.is_active = True
                #user.set_password(registration_data['password'])  # Hash the password!
                #user.save()
                
                # NOW send admin notification (AFTER OTP success!)
                send_email_by_type(
                    'request',
                    settings.EMAIL_HOST_USER,
                    {
                        'requester_name': registration_data['username'],
                        'requester_email': registration_data['email'],
                        'user_id': pending_user_id
                    }
                )
                
                send_email_by_type('registration', registration_data['email'])
                
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

# def registration_view(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         email = request.POST.get('recipient_email')
#         password = request.POST.get('password')
        
#         # 1. Validate basic input (optional)
#         if (not email or '@' not in email): # or not password:
#             messages.error(request, 'Please fill all fields')
#             return render(request, 'signup.html')
        
#         # 2. IMMEDIATELY store registration data in session
#         request.session['registration_data'] = {
#             'username': username,
#             'email': email
#         }
        
#         send_otp_view(request, email)  # Send OTP to user's email
#         return redirect('otp_verify')  # Redirect to OTP verification page
    
#     # GET request - show empty form
#     return render(request, 'registration.html')


from django.shortcuts import render
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import Organization, User, Report, Risk
from .serializers import OrganizationSerializer, UserSerializer, ReportSerializer, RiskSerializer
from django.contrib.auth import get_user_model

User = get_user_model()

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
