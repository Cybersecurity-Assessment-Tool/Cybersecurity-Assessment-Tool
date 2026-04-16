import logging

from django.conf import settings
from django.test.utils import override_settings
from django_q.tasks import async_task

from api.utils.email_factory import send_email_by_type

logger = logging.getLogger(__name__)


def _send_with_console_fallback(email_type, recipient, context_overrides=None):
    """Try the configured backend first, then fall back to the console backend in local dev."""
    try:
        return send_email_by_type(email_type, recipient, context_overrides)
    except Exception:
        logger.exception('Email delivery failed for %s; retrying with console backend.', email_type)
        with override_settings(EMAIL_BACKEND='django.core.mail.backends.console.EmailBackend'):
            return send_email_by_type(email_type, recipient, context_overrides)


def queue_email(email_type, recipient, context_overrides=None):
    """Send immediately in local/test environments, otherwise queue via Django-Q."""
    if not recipient:
        logger.warning('Skipping %s email because no recipient was provided.', email_type)
        return None

    use_async = getattr(settings, 'ASYNC_EMAIL_ENABLED', False) and not getattr(settings, 'TESTING', False)

    if not use_async:
        return _send_with_console_fallback(email_type, recipient, context_overrides)

    try:
        return async_task(
            'api.utils.email_factory.send_email_by_type',
            email_type,
            recipient,
            context_overrides,
        )
    except Exception:
        logger.exception('Falling back to synchronous send for %s email.', email_type)
        return _send_with_console_fallback(email_type, recipient, context_overrides)