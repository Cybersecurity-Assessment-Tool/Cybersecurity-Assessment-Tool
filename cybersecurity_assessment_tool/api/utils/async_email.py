import logging

from django_q.tasks import async_task

logger = logging.getLogger(__name__)


def send_email_task(email_type: str, recipient: str, context_overrides: dict | None = None):
    """
    Worker-side task executed by a Django-Q2 worker process.

    Delegates to send_email_by_type so all template/rendering logic
    stays in one place.  Re-raises on failure so Django-Q2 can record
    the task as failed and trigger its retry/alert mechanism.
    """
    # Local import avoids any circular-import issues at module load time.
    from api.utils.email_factory import send_email_by_type

    try:
        send_email_by_type(email_type, recipient, context_overrides)
        logger.info("Async email sent: type=%s  recipient=%s", email_type, recipient)
    except Exception as exc:
        logger.error(
            "Async email failed: type=%s  recipient=%s  error=%s",
            email_type, recipient, exc, exc_info=True,
        )
        raise


def send_email_async(email_type: str, recipient: str, context_overrides: dict | None = None) -> None:
    """
    Queue an email to be delivered in the background by a Django-Q2 worker.

    Drop-in async replacement for send_email_by_type().  For email types
    that require a return value (e.g. OTP), generate the value *before*
    calling this function and pass it in via context_overrides so the
    caller can store it (e.g. in the session) immediately.

    Example — non-OTP::

        send_email_async('approval', user.email, {'username': user.username})

    Example — OTP (pre-generate so it can be stored in the session)::

        from api.utils.send_otp_mail import generate_otp
        otp = generate_otp()
        request.session['otp_code'] = otp
        send_email_async('otp', recipient, {'otp': otp})
    """
    async_task(
        "api.utils.async_email.send_email_task",
        email_type,
        recipient,
        context_overrides,
        task_name=f"email_{email_type}_{recipient}",
    )
    logger.debug("Queued async email: type=%s  recipient=%s", email_type, recipient)
