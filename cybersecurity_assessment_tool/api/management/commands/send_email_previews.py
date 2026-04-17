from email.mime.image import MIMEImage
from pathlib import Path

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.core.management.base import BaseCommand, CommandError
from django.template.loader import render_to_string
from django.utils.html import strip_tags


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


class Command(BaseCommand):
    help = "Send preview/test emails for all RePortly email templates."

    def add_arguments(self, parser):
        parser.add_argument(
            "--recipient",
            required=True,
            help="Email address to receive the preview emails.",
        )
        parser.add_argument(
            "--scenario",
            default="all",
            choices=[
                "all",
                "otp",
                "registration",
                "approval",
                "rejection",
                "request",
                "invite",
                "invite_accepted",
                "report",
                "verify_email",
                "test",
            ],
            help="Which preview scenario to send. Defaults to all.",
        )

    def handle(self, *args, **options):
        recipient = options["recipient"].strip()
        scenario_name = options["scenario"]

        if not recipient:
            raise CommandError("A recipient email address is required.")

        contact_email = (
            getattr(settings, "ADMIN_EMAIL_INBOX", "")
            or getattr(settings, "DEFAULT_FROM_EMAIL", "")
            or getattr(settings, "EMAIL_HOST_USER", "")
            or "support@example.com"
        ).strip()
        sender = (
            getattr(settings, "DEFAULT_FROM_EMAIL", "")
            or getattr(settings, "EMAIL_HOST_USER", "")
            or contact_email
        ).strip()
        if not sender:
            raise CommandError("DEFAULT_FROM_EMAIL, EMAIL_HOST_USER, or ADMIN_EMAIL_INBOX must be configured before sending previews.")
        login_url = "http://localhost:8000/accounts/login/"

        scenarios = {
            "otp": {
                "subject": "[Preview] Verification Code",
                "template": "emails/otp-verification.html",
                "context": {
                    "otp": "482913",
                    "contact_email": contact_email,
                },
            },
            "registration": {
                "subject": "[Preview] Registration Request Sent Successfully",
                "template": "emails/confirmation.html",
                "context": {
                    "username": "Onella",
                    "contact_email": contact_email,
                },
            },
            "approval": {
                "subject": "[Preview] Account Approved - Welcome Aboard!",
                "template": "emails/approval_accepted.html",
                "context": {
                    "username": "Onella",
                    "login_url": login_url,
                    "contact_email": contact_email,
                },
            },
            "rejection": {
                "subject": "[Preview] Account Request Rejected",
                "template": "emails/approval_rejected.html",
                "context": {
                    "username": "Onella",
                    "company": "RePortly",
                    "role": "Observer",
                    "contact_email": contact_email,
                },
            },
            "request": {
                "subject": "[Preview] New Account Request - Action Required",
                "template": "emails/admin_request.html",
                "context": {
                    "requester_name": "Jordan Example",
                    "requester_email": "jordan@example.com",
                    "company": "RePortly",
                    "role": "Organization Admin",
                    "approve_url": "http://localhost:8000/admin/approve-preview/",
                    "reject_url": "http://localhost:8000/admin/reject-preview/",
                    "contact_email": contact_email,
                },
            },
            "invite": {
                "subject": "[Preview] Account invitation from Organization Administrator",
                "template": "emails/org_admin_invite.html",
                "context": {
                    "inviter_name": "Jamie Org Admin",
                    "inviter_role": "Org Admin",
                    "inviter_company": "RePortly",
                    "company": "RePortly",
                    "role": "Observer",
                    "invite_link": "http://localhost:8000/accounts/invite/sample-token/",
                    "contact_email": contact_email,
                },
            },
            "invite_accepted": {
                "subject": "[Preview] Team Member Joined Your Organization",
                "template": "emails/invite_accepted.html",
                "context": {
                    "admin_name": "Onella",
                    "member_name": "Alex Analyst",
                    "member_email": "alex@example.com",
                    "company": "RePortly",
                    "role": "Analyst",
                    "login_url": login_url,
                    "contact_email": contact_email,
                },
            },
            "report": {
                "subject": "[Preview] Your Security Report is Ready",
                "template": "emails/report_ready.html",
                "context": {
                    "generated_date": "April 10, 2026 3:30 PM",
                    "report_id": "SEC-2026-0410-001",
                    "report_type": "Comprehensive Cybersecurity Assessment",
                    "login_url": "http://localhost:8000/login/?next=/reports/SEC-2026-0410-001/",
                    "contact_email": contact_email,
                },
            },
            "verify_email": {
                "subject": "[Preview] Verify Your Email Address",
                "template": "emails/user_verification_template.html",
                "context": {
                    "verification_url": "http://localhost:8000/accounts/verify/sample/",
                    "contact_email": contact_email,
                },
            },
            "test": {
                "subject": "[Preview] Test Email",
                "template": "emails/test.html",
                "context": {
                    "username": "Onella",
                    "contact_email": contact_email,
                },
            },
        }

        selected = scenarios.items() if scenario_name == "all" else [(scenario_name, scenarios[scenario_name])]

        sent_count = 0
        for key, config in selected:
            html_content = render_to_string(config["template"], config["context"])
            text_content = strip_tags(html_content).strip() or config["subject"]

            message = EmailMultiAlternatives(
                subject=config["subject"],
                body=text_content,
                from_email=sender,
                to=[recipient],
                reply_to=[contact_email] if contact_email else None,
            )
            message.mixed_subtype = "related"
            message.attach_alternative(html_content, "text/html")
            _attach_inline_logo(message)
            message.send()

            sent_count += 1
            self.stdout.write(self.style.SUCCESS(f"Sent '{key}' preview to {recipient}"))

        self.stdout.write(self.style.SUCCESS(f"Done. {sent_count} preview email(s) sent to {recipient}."))
