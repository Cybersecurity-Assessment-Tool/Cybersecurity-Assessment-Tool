from django.core.exceptions import ObjectDoesNotExist
from django.core.files.base import ContentFile
from django.db import transaction
from ..models import Report, User, Organization
from datetime import time
import json

@transaction.atomic
def create_report(
    user_created: User,
    organization: Organization,
    name: str,
    date_created,
    started,
    completed=None,
    report_text=None # JSONField content (dict or list in Python)
) -> Report:
    """
    Stores (creates) a new Report object in the database.
    ...
    Returns:
        Report: The newly created Report instance.
    """
    report = Report.objects.create(
        user_created=user_created,
        organization=organization,
        report_name=name,
        date_created=date_created,
        started=started,
        completed=completed,
        report_text=report_text
    )
    return report

def get_report_by_id(report_id: str) -> Report | None:
    """
    Retrieves a single Report object by its primary key (report_id).

    Args:
        report_id (str): The UUID of the report to retrieve.

    Returns:
        Report | None: The Report instance if found, otherwise None.
    """
    try:
        return Report.objects.get(pk=report_id)
    except ObjectDoesNotExist:
        return None

def list_reports_by_user(user: User):
    """
    Retrieves a queryset of all reports created by a specific user.

    Args:
        user (User): The User instance to filter by.

    Returns:
        django.db.models.query.QuerySet: A queryset of Report objects.
    """
    return Report.objects.filter(user_created=user).order_by('-date_created')

def get_report_file_content(report_id: str) -> str | None:
    """
    Retrieves the JSON content of the file associated with a report.

    Args:
        report_id (str): The UUID of the report.

    Returns:
        bytes | None: The JSON content converted to JSON formatted string of the file, or None if the report/file is not found.
    """
    try:
        report = Report.objects.get(pk=report_id)
        
        # The report_text is a JSONField, which Django typically converts to 
        # a Python dict/list. We need to convert it back to a JSON formatted string.
        if report.report_text is not None:
            # Use json.dumps to convert the Python object back to a JSON string
            return json.dumps(report.report_text, indent=4)
        else:
            return None

    except ObjectDoesNotExist:
        return None