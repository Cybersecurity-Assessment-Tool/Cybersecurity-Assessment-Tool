import random
from email.mime.image import MIMEImage
from pathlib import Path
from django.core.mail import send_mail, EmailMultiAlternatives
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from django.template.loader import render_to_string
from django.urls import reverse


def _attach_inline_logo(message):
    logo_path = Path(settings.BASE_DIR) / 'static' / 'images' / 'logo.png'
    if not logo_path.exists():
        return

    try:
        with logo_path.open('rb') as logo_file:
            logo = MIMEImage(logo_file.read())
        logo.add_header('Content-ID', '<reportly-logo>')
        logo.add_header('Content-Disposition', 'inline', filename='logo.png')
        message.attach(logo)
    except Exception:
        return

def _get_app_base_url():
    return (
        getattr(settings, 'APP_BASE_URL', '').strip()
        or getattr(settings, 'SITE_URL', '').strip()
        or getattr(settings, 'MICROSOFT_OAUTH_REDIRECT_BASE_URL', '').strip()
        or 'http://localhost:8000'
    ).rstrip('/')


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
    RePortly Team
    """
    
    support_email = (
        getattr(settings, 'ADMIN_EMAIL_INBOX', '').strip()
        or getattr(settings, 'DEFAULT_FROM_EMAIL', '').strip()
        or getattr(settings, 'EMAIL_HOST_USER', '').strip()
        or 'noreply@localhost'
    )
    sender_email = (
        getattr(settings, 'DEFAULT_FROM_EMAIL', '').strip()
        or getattr(settings, 'EMAIL_HOST_USER', '').strip()
        or support_email
    )
    config['context']['contact_email'] = support_email
    config['context']['password_reset_url'] = f"{_get_app_base_url()}{reverse('password_reset')}"

    # Render HTML template (same as test_email.py)
    html_content = render_to_string(config['template'], config['context'])
    
    # Send using EmailMultiAlternatives (same as test_email.py)
    from_email = sender_email
    msg = EmailMultiAlternatives(
        config['subject'],
        text_content,
        from_email,
        [recipient],
        reply_to=[support_email] if support_email else None,
    )
    msg.mixed_subtype = 'related'
    msg.attach_alternative(html_content, "text/html")
    _attach_inline_logo(msg)
    msg.send()
    
    print(f"✅ OTP email sent to {recipient}")
    return otp  # Return for session storage