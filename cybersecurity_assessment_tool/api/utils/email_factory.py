from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from .send_otp_mail import generate_otp

def send_email_by_type(email_type, recipient=None, context_overrides=None):
    """
    Universal email sender using your exact test_email.py templates
    
    Args:
        email_type (str): 'otp', 'approval', 'rejection', 'report', etc.
        recipient (str): Email recipient (defaults to hardcoded)
        context_overrides (dict): Override default context values
    """
    recipient = recipient
    
    # EXACT SAME templates as your test_email.py
    # Serves as an outline for which fields to pass for each email type. You can expand ot update the context as needed.
    email_templates = {
        # Verificaiton OTP email
        "otp": {
            "subject": "Verification Code",
            "template": "emails/otp-verification.html",
            "context": {"otp": generate_otp()}
        },
        
        # Email after user submits registration form (before approval)
        "registration": {
            "subject": "Registration Request Sent Successfully",
            "template": "emails/confirmation.html",
            "context": {"username": "Test User"}
        },
        
        # Email to user after admin approves their account request
        "approval": {
            "subject": "Account Approved - Welcome Aboard!",
            "template": "emails/approval_accepted.html", 
            "context": {"username": "Test User", "login_url": "http://localhost:8000/accounts/login/"}
        },
        
        # Email to user after admin rejects their account request
        "rejection": {
            "subject": "Account Request Rejected",
            "template": "emails/approval_rejected.html",
            "context": {"username": "Test User", "company": "Cybersecurity Inc.", "role": "Manager"}
        },
        
        # Request email sent to admin when new user registers
        "request": {
            "subject": "New Account Request - Action Required",
            "template": "emails/admin_request.html",
            "context": {
                "requester_name": "Test User",
                "requester_email": "",
                "company": "Cybersecurity Inc.",
                "role": "Org Admin"
            }
        },
        
        # Invite email sent to new user when org admin invites them to join
        "invite": {
            "subject": "Account invitation from Executive",
            "template": "emails/executive_invite.html",
            "context": {
                "inviter_name": "Jane Executive",
                "inviter_role": "Executive",
                "inviter_company": "Cybersecurity Inc.",
                "company": "Cybersecurity Inc.",
                "role": "Manager",
                "invite_link": "http://localhost:8000/invite/abc123xyz/"
            }
        },
        
        # Report ready email sent to user when their security report is generated
        "report": {
            "subject": "Your Security Report is Ready",
            "template": "emails/report_ready.html",
            "context": {
                "generated_date": "March 5, 2026 10:44 AM EST",
                "report_id": "SEC-2026-0305-001",
                "report_type": "Comprehensive Vulnerability Assessment",
                "login_url": "http://localhost:8000/login/?next=/reports/SEC-2026-0305-001/"
            }
        }
    }
    
    config = email_templates[email_type]
    
    # Override context if provided
    if context_overrides:
        print("Overriding context with:", context_overrides)
        config['context'].update(context_overrides)
        
    config['context']['contact_email'] = settings.DEFAULT_FROM_EMAIL
    
    # Update recipient in context for templates that use it
    # if 'requester_email' in config['context']:
    #     config['context']['requester_email'] = recipient
    
    # Plain text fallback (same as test_email.py)
    text_content = f"""
    Hello,

    {config['subject']}

    This email was sent using Django email factory.

    Regards,
    Cybersecurity Team
    """
    
    print("FINAL CONTEXT before render:", config['context'])  # Add this line

    
    # Render HTML template
    html_content = render_to_string(config['template'], config['context'])
    
    # Send using EmailMultiAlternatives (same as test_email.py)
    from_email = getattr(settings, 'DEFAULT_FROM_EMAIL') or settings.DEFAULT_FROM_EMAIL
    msg = EmailMultiAlternatives(
        config['subject'],
        text_content,
        from_email,
        [recipient]
    )
    msg.attach_alternative(html_content, "text/html")
    msg.send()
    
    print(f"✅ {config['subject']} sent to {recipient}")
    return config['context']
