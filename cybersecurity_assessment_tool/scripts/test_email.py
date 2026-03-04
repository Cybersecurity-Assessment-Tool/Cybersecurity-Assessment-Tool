from api.utils.send_mail import send_mail

def run(*args):
    """
    Usage:
        python manage.py runscript send_email
        python manage.py runscript send_email --script-args test@example.com
    """

    # Get recipient from script args (optional)
    #recipient = args[0] if args else "corabigsky@gmail.com"

    subject = "SMTP Email from Django RunScript"
    message = """
    Hello,

    This email was sent using Django runscript via SMTP.

    Regards,
    Django App
    """

    send_mail("onellamoitra@gmail.com", subject, message)

    # or, you can short circuit it like this:
    # send_mail("corabigsky@gmail.com", "simple subject", "simple message")
