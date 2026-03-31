from django_q.tasks import async_task
from api.utils.email_factory import send_email_by_type

def queue_email(email_type, recipient, context_overrides=None):
    """Pushes the email sending to the background via django-q"""
    async_task('api.utils.email_factory.send_email_by_type', email_type, recipient, context_overrides)