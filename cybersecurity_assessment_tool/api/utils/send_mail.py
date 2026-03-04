from django.core.mail import EmailMessage
from django.conf import settings


def send_mail(recipient, subject, message):
    try:
        email = EmailMessage(
            subject=subject,
            body=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient],
        )

        email.send(fail_silently=False)

        return True

    except Exception as e:
        return False

        # todo - add error logging here
