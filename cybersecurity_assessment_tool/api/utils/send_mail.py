from django.core.mail import EmailMultiAlternatives
from django.conf import settings

def send_mail(to_email, subject, message, html_message=None):
    email = EmailMultiAlternatives(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [to_email]  # <-- already a list
    )

    if html_message:
        email.attach_alternative(html_message, "text/html")

    email.send()

# ON THE CHOPPING BLOCK