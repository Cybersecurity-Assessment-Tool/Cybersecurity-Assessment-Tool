from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from api.utils.send_otp_mail import send_otp_email
from api.utils.send_otp_mail import generate_otp
from api.utils.send_mail import send_mail

def run(*args):
    recipient = "onellamoitra@gmail.com"
    email_type = args[0] if args else "registration"  # Default to registration
    
    email_templates = {
        "invite": {
            "subject": "Account invitation from executive",
            "template": "emails/executive_invite.html",
            "context": {
                "inviter_name": "Jane Executive",
                "inviter_role": "Executive",
                "inviter_company": "Cybersecurity Inc.",
                "company": "Cybersecurity Inc.",
                "role": "Manager",
                "invite_link": "http://localhost:8000/invite/abc123xyz/"
            },
            "to": "onellamoitra@gmail.com"
        },
        "otp": {
            "subject": "Verification Code",  # Fixed subject
            "template": "emails/otp-verification.html",
            "context": {"otp": generate_otp()}  # ← FIXED: Generate OTP here
        },
        "registration": {
            "subject": "Registration Request Sent Successfully",
            "template": "emails/confirmation.html",
            "context": {"username": "Test User"}
        },
        "request": {
            "subject": "New Account Request - Action Required",
            "template": "emails/admin_request.html",
            "context": {
                "requester_name": "John Doe",
                "requester_email": "onellamoitra@gmail.com",
                "company": "Cybersecurity Inc.",
                "role": "Manager"
            }
        },
        "approval": {
            "subject": "Account Approved - Welcome Aboard!",
            "template": "emails/approval_accepted.html", 
            "context": {"username": "Test User"}
        },
        "rejection": {
            "subject": "Account Request Rejected",
            "template": "emails/approval_rejected.html",
            "context": {
                "username": "Test User",
                "company": "Cybersecurity Inc.",
                "role": "Manager"
            }
        },
        "report": {
            "subject": "Your Security Report is Ready",
            "template": "emails/report_ready.html",
            "context": {
                "generated_date": "March 5, 2026 3:55 AM EST",
                "report_id": "SEC-2026-0305-001",
                "report_type": "Comprehensive Vulnerability Assessment",
                "login_url": "http://localhost:8000/login/?next=/reports/SEC-2026-0305-001/"
            },
            "to": "onellamoitra@gmail.com"
        }
    }
    
    # Get email config
    config = email_templates.get(email_type, email_templates[email_type])
    
    # Print OTP for debugging
    #if email_type == "otp":
    #    print(f"🔢 Generated OTP: {config['context']['otp']}")
    
    # Plain text fallback
    text_content = f"""
    Hello,

    {config['subject']}

    This email was sent using Django runscript.

    Regards,
    Cybersecurity Team
    """
    
    # Render HTML template
    html_content = render_to_string(config['template'], config['context'])
    
    # Send using EmailMultiAlternatives
    msg = EmailMultiAlternatives(
        config['subject'],
        text_content,
        settings.EMAIL_HOST_USER,
        [recipient]
    )
    msg.attach_alternative(html_content, "text/html")
    msg.send()
    
    print(f"✅ {config['subject']} sent to {recipient}")
