from django.core.mail import EmailMultiAlternatives
from django.conf import settings

def send_mail(to_email, subject, message, html_message=None):
    contact_email = (
        getattr(settings, 'ADMIN_EMAIL_INBOX', '').strip()
        or getattr(settings, 'DEFAULT_FROM_EMAIL', '').strip()
        or getattr(settings, 'EMAIL_HOST_USER', '').strip()
        or 'noreply@localhost'
    )
    sender = (
        getattr(settings, 'DEFAULT_FROM_EMAIL', '').strip()
        or getattr(settings, 'EMAIL_HOST_USER', '').strip()
        or contact_email
    )
    email = EmailMultiAlternatives(
        subject,
        message,
        sender,
        [to_email],  # <-- already a list
        reply_to=[contact_email] if contact_email else None,
    )

    if html_message:
        email.attach_alternative(html_message, "text/html")

    email.send()

# ON THE CHOPPING BLOCK