from django.shortcuts import render, redirect
from django.contrib import messages
from django.conf import settings
from api.utils.email_factory import send_email_by_type  # ← NEW IMPORT
import time

# Simple session-based OTP storage (use Redis/Cache in production)
def otp_verify_view(request):
    if request.method == 'POST':
        print("=== DEBUG INFO ===")
        print(f"POST data: {request.POST}")  # See ALL form data
        
        # Get OTP from all 6 inputs
        otp_input = ''.join([
            request.POST.get(f'otp{i}', '') for i in range(1, 7)
        ]).strip()
        
        print(f"User entered OTP: '{otp_input}'")  # What user typed
        print(f"Stored OTP: '{request.session.get('otp_code')}'")  # What we expect
        
        stored_otp = request.session.get('otp_code')
        otp_created = request.session.get('otp_created')
        
        print(f"OTP created time: {otp_created}")
        print(f"Current time: {time.time()}")
        print(f"Time diff: {time.time() - otp_created if otp_created else 'N/A'}")
        
        # Check if OTP expired (5 minutes)
        if not stored_otp or not otp_created or (time.time() - otp_created > 300):
            messages.error(request, 'OTP expired or not found. Please request a new one.')
            return render(request, 'otp_verify.html')
        
        if otp_input == stored_otp:
            # SUCCESS - Clear session and redirect
            request.session.pop('otp_code', None)
            request.session.pop('otp_created', None)
            messages.success(request, 'OTP verified successfully!')
            return redirect('dashboard')  # Change to your dashboard URL
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
    
    return render(request, 'otp_verify.html')

def send_otp_view(request):
    """Send OTP to user using email_factory"""
    recipient = "onellamoitra@gmail.com"  # Get from form/session in production
    
    # Send OTP using your new factory (handles generation + sending)
    context = send_email_by_type('otp', recipient)
    otp = context['otp']  # Extract from returned context
    
    print(f"Generated OTP: {otp}")  # For debugging, remove in production
    
    # Store in session
    request.session['otp_code'] = otp
    request.session['otp_created'] = time.time()
    
    messages.success(request, 'OTP sent to your email!')
    return redirect('otp_verify')
