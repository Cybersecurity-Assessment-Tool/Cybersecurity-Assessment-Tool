import random
from django.core.mail import send_mail, EmailMultiAlternatives
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from django.template.loader import render_to_string

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(recipient, otp=None):
    """
    Send OTP email using the exact same template/rendering as test_email.py
    """
    if otp is None:
        otp = generate_otp()
    
    # OTP-specific config (matches test_email.py exactly)
    config = {
        "subject": "Verification Code",
        "template": "emails/otp-verification.html",
        "context": {"otp": otp}
    }
    
    # Plain text fallback (same as test_email.py)
    text_content = f"""
    Hello,

    Verification Code: {otp}

    This is your one-time verification code.
    It expires in 5 minutes.

    Regards,
    Cybersecurity Team
    """
    
    # Render HTML template (same as test_email.py)
    html_content = render_to_string(config['template'], config['context'])
    
    # Send using EmailMultiAlternatives (same as test_email.py)
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None) or settings.EMAIL_HOST_USER
    msg = EmailMultiAlternatives(
        config['subject'],
        text_content,
        from_email,
        [recipient]
    )
    msg.attach_alternative(html_content, "text/html")
    msg.send()
    
    print(f"✅ OTP email sent to {recipient}")
    return otp  # Return for session storage