import json
from api.models import Report, Risk
from django.core.exceptions import ValidationError

def print_report(report_id=None):
    print("\n" + "="*60)
    print("🔍 DECRYPTED REPORT DATA")
    print("="*60)
    
    try:
        # Fetch specific ID if provided, otherwise grab the latest
        if report_id:
            report = Report.objects.get(report_id=report_id)
        else:
            report = Report.objects.order_by('-started').first()
            print("(Showing latest report because no ID was provided)")
            
        if report:
            print(f"Report Name: {report.report_name}")
            print(f"Report ID:   {report.report_id}")
            print("-" * 60)
            print("Decrypted Report Text (JSON):")
            print(json.dumps(report.report_text, indent=4))
        else:
            print("No reports found in the database.")
            
    except Report.DoesNotExist:
        print(f"❌ Error: Report with ID '{report_id}' does not exist.")
    except ValidationError:
        print(f"❌ Error: '{report_id}' is not a valid UUID format.")

def print_risk(risk_id=None):
    print("\n" + "="*60)
    print("🔍 DECRYPTED RISK DATA")
    print("="*60)
    
    try:
        if risk_id:
            risk = Risk.objects.get(risk_id=risk_id)
        else:
            risk = Risk.objects.last()
            print("(Showing latest risk because no ID was provided)")

        if risk:
            print(f"Risk Name: {risk.risk_name}")
            print(f"Risk ID:   {risk.risk_id}")
            print(f"Severity:  {risk.severity}")
            print("-" * 60)
            print(f"Decrypted Overview (Text):\n{risk.overview}\n")
            print(f"Decrypted Affected Elements (Text):\n{risk.affected_elements}\n")
            print("Decrypted Recommendations (JSON):")
            print(json.dumps(risk.recommendations, indent=4))
        else:
            print("No risks found in the database.")
            
    except Risk.DoesNotExist:
        print(f"❌ Error: Risk with ID '{risk_id}' does not exist.")
    except ValidationError:
        print(f"❌ Error: '{risk_id}' is not a valid UUID format.")

def run(*args):
    """
    Usage:
        python manage.py runscript check_encryption
        python manage.py runscript check_encryption --script-args "Your prompt here"
    """
    command = args[0].lower()
    target_id = args[1] if len(args) > 1 else None

    # Route the command to the correct function
    if command == 'report':
        print_report(target_id)
    elif command == 'risk':
        print_risk(target_id)
    elif command == 'latest':
        print_report()
        print_risk()
    else:
        print(f"❌ Unknown argument: '{command}'. Please use 'report', 'risk', or 'latest'.")