from email.mime.image import MIMEImage
from pathlib import Path

from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.urls import reverse
from .send_otp_mail import generate_otp


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


def send_email_by_type(email_type, recipient=None, context_overrides=None):
    """
    Universal email sender using your exact test_email.py templates
    
    Args:
        email_type (str): 'otp', 'approval', 'rejection', 'report', etc.
        recipient (str): Email recipient (defaults to hardcoded)
        context_overrides (dict): Override default context values
    """
    recipient = recipient
    
    # Call the helper function once at the top
    base_url = _get_app_base_url()
    
    email_templates = {
        "otp": {
            "subject": "Verification Code",
            "template": "emails/otp-verification.html",
            "context": {"otp": generate_otp()}
        },
        "registration": {
            "subject": "Registration Request Sent Successfully",
            "template": "emails/confirmation.html",
            "context": {"username": "Test User"}
        },
        "approval": {
            "subject": "Account Approved - Welcome Aboard!",
            "template": "emails/approval_accepted.html", 
            "context": {"username": "Test User", "login_url": f"{base_url}/accounts/login/"}
        },
        "rejection": {
            "subject": "Account Request Rejected",
            "template": "emails/approval_rejected.html",
            "context": {"username": "Test User", "company": "RePortly", "role": "Manager"}
        },
        "request": {
            "subject": "New Account Request - Action Required",
            "template": "emails/admin_request.html",
            "context": {
                "requester_name": "Test User",
                "requester_email": "",
                "company": "RePortly",
                "role": "Org Admin"
            }
        },
        "invite": {
            "subject": "Account invitation from Executive",
            "template": "emails/executive_invite.html",
            "context": {
                "inviter_name": "Jane Executive",
                "inviter_role": "Executive",
                "inviter_company": "RePortly.",
                "company": "RePortly",
                "role": "Manager",
                "invite_link": f"{base_url}/invite/abc123xyz/"
            }
        },
        "invite_accepted": {
            "subject": "Team Member Joined Your Organization",
            "template": "emails/invite_accepted.html",
            "context": {
                "admin_name": "Org Admin",
                "member_name": "New Team Member",
                "member_email": "member@example.com",
                "company": "RePortly",
                "role": "Observer",
                "login_url": f"{base_url}/accounts/login/",
            }
        },
        "report": {
            "subject": "Your Security Report is Ready",
            "template": "emails/report_ready.html",
            "context": {
                "generated_date": "March 5, 2026 10:44 AM EST",
                "report_url": f"{base_url}/reports/123e4567-e89b-12d3-a456-426614174000/"
            }
        }
    }
    
    config = email_templates[email_type]
    
    # Override context if provided
    if context_overrides:
        print("Overriding context with:", context_overrides)
        config['context'].update(context_overrides)

    support_email = (
        getattr(settings, 'ADMIN_EMAIL_INBOX', '').strip()
        or str(config['context'].get('contact_email', '')).strip()
        or getattr(settings, 'DEFAULT_FROM_EMAIL', '').strip()
        or getattr(settings, 'EMAIL_HOST_USER', '').strip()
        or 'noreply@localhost'
    )
    sender_email = (
        getattr(settings, 'DEFAULT_FROM_EMAIL', '').strip()
        or getattr(settings, 'EMAIL_HOST_USER', '').strip()
        or support_email
        or 'noreply@localhost'
    )
    config['context']['contact_email'] = support_email
    config['context'].setdefault('password_reset_url', f"{_get_app_base_url()}{reverse('password_reset')}")
    
    # Update recipient in context for templates that use it
    # if 'requester_email' in config['context']:
    #     config['context']['requester_email'] = recipient
    
    # Plain text fallback (same as test_email.py)
    text_content = f"""
    Hello,

    {config['subject']}

    This email was sent using Django email factory.

    Regards,
    RePortly Team
    """
    
    print("FINAL CONTEXT before render:", config['context'])  # Add this line

    
    # Render HTML template
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
    
    print(f"✅ {config['subject']} sent to {recipient}")
    return config['context']
