import json
from django.forms.models import model_to_dict
from typing import Any, Tuple, List, Optional
from django.db import transaction
from django.utils import timezone

from ..models import Report, Risk, Organization, User
from .ai_generation_service import ai_generation_service

# EXAMPLE CALL FROM FRONTEND
# from django.http import JsonResponse
# from .gemini_client import generate_and_process_report

# def trigger_report_generation(request):
#     # 1. Extract inputs from the frontend request
#     org_id = request.POST.get('organization_id')
#     user_id = request.user.id # Or request.POST.get('user_id')
#     context_data = request.POST.get('scan_results_context') 
    
#     # 2. Call your client
#     report, risks = generate_and_process_report(org_id, user_id, context_data)
    
#     if report:
#         return JsonResponse({"status": "success", "report_id": report.id})
#     else:
#         return JsonResponse({"status": "error", "message": "Failed to generate"}, status=500)

# Define a sorting map for severities to translate strings to sortable integers

SEVERITY_WEIGHTS = {
    "Critical": 1,
    "High": 2,
    "Medium": 3,
    "Low": 4,
    "Info": 5
}

def get_severity_weight(severity_str: str) -> int:
    """Helper to safely get the integer weight of a severity string."""
    # Default to 6 (lowest priority) if the AI generates an unexpected string
    return SEVERITY_WEIGHTS.get(severity_str.capitalize(), 6)

def get_questionnaire_dict(org: Organization) -> dict:
    return {
        "Questionnaire Review": {
            "Do you require MFA to access email?": "Yes" if org.require_mfa_email else "No",
            "Do you require MFA to log into computers?": "Yes" if org.require_mfa_computer else "No",
            "Do you require MFA to access sensitive data systems?": "Yes" if org.require_mfa_sensitive_data else "No",
            "Does your organization have an employee acceptable use policy?": "Yes" if org.employee_acceptable_use_policy else "No",
            "Does your organization do security awareness training for new employees?": "Yes" if org.training_new_employees else "No",
            "Does your organization do security awareness training for all employees at least once per year?": "Yes" if org.training_once_per_year else "No"
        }
    }

def build_current_risks_dict(organization_id: int) -> dict:
    """
    Fetches existing active risks for an organization and formats them 
    into a dictionary that the AI service expects.
    """
    existing_risks = Risk.objects.filter(organization_id=organization_id, is_archived=False)
    
    current_risks = {
        "all_vulnerabilities": [
            {
                "risk_name": risk.risk_name,
                "overview": risk.overview,
                "severity": risk.severity,
                "affected_elements": [e.strip() for e in risk.affected_elements.split(",")] if risk.affected_elements else []
            }
            for risk in existing_risks
        ]
    }
    return current_risks

def _convert_scan_obj_to_dict(scan_obj: Any) -> dict:
    """Safely converts the scan_obj into a dictionary for JSON injection."""
    if not scan_obj:
        return {}
    
    if isinstance(scan_obj, dict):
        return scan_obj
    
    if isinstance(scan_obj, str):
        try:
            return json.loads(scan_obj)
        except json.JSONDecodeError:
            return {"Raw Data": scan_obj}
            
    # If it's a Django Model instance, convert it to a dictionary
    if hasattr(scan_obj, '__dict__'):
        try:
            return model_to_dict(scan_obj)
        except Exception:
            return {"Raw Data": str(scan_obj)}
            
    return {"Raw Data": str(scan_obj)}

def _inject_overview_scan_and_questionnaire(report_data: dict, org: Organization, scan_obj: Any = None) -> dict:
    """
    Injects the Overview, Scan Findings, and Questionnaire Review sections at the top 
    of the AI-generated report data using information from the database.
    """
    scan_findings_dict = _convert_scan_obj_to_dict(scan_obj)
    
    new_section_data = {
        "Overview": {
            "Organization Name": org.org_name,
            "Email Domain": org.email_domain,
            "Website Domain": org.website_domain,
            "External IP Address": org.external_ip,
            "Report Date": timezone.now().strftime('%Y-%m-%d')
        },
        "Scan Findings": scan_findings_dict,
        "Questionnaire Review": {
            "Do you require MFA to access email?": "Yes" if org.require_mfa_email else "No",
            "Do you require MFA to log into computers?": "Yes" if org.require_mfa_computer else "No",
            "Do you require MFA to access sensitive data systems?": "Yes" if org.require_mfa_sensitive_data else "No",
            "Does your organization have an employee acceptable use policy?": "Yes" if org.employee_acceptable_use_policy else "No",
            "Does your organization do security awareness training for new employees?": "Yes" if org.training_new_employees else "No",
            "Does your organization do security awareness training for all employees at least once per year?": "Yes" if org.training_once_per_year else "No"
        }
    }

    if "report" in report_data and isinstance(report_data["report"], list):
        for i, report_item in enumerate(report_data["report"]):
            rebuilt_report_item = {}
            
            for key, value in new_section_data.items():
                rebuilt_report_item[key] = value
                
            for key, value in report_item.items():
                rebuilt_report_item[key] = value
                
            report_data["report"][i] = rebuilt_report_item

    return report_data

def generate_and_process_report(
    organization_id: str, 
    user_id: str, 
    context_data: str,
    scan_obj: Optional[Any] = None
) -> Tuple[Optional[Report], Optional[List[Risk]]]:
    """
    Acts as the client to gather DB fields, call the AI service, 
    sort the resulting data, inject database context, and save objects.
    Please have the context_data (network scan) be a JSON string, as the AI takes strings only. 
    Do not load it as a dictionary.
    """
    # Fetch the database records
    org = Organization.objects.get(organization_id=organization_id)
    user = User.objects.get(user_id=user_id) if user_id else None
        
    # 1. Fetch current risks
    current_risks = build_current_risks_dict(organization_id)
    
    # 2. Fetch the questionnaire information
    questionnaire = get_questionnaire_dict(org)

    # 3. Call the AI generation service (pure AI logic, no database IDs needed)
    report_data, risks_data = ai_generation_service(questionnaire, current_risks, context_data)

    if report_data is None or risks_data is None:
        print("[ERROR] AI Service failed to generate report or risks data.")
        # FIX: Update the scan status to FAILED so the UI knows to stop
        if scan_obj:
            scan_obj.status = 'FAILED'
            scan_obj.save(update_fields=['status'])
        return None, None
    
    ## DEBUG pt 1
    # print("="*60)
    # print("GEMINI_CLIENT: risks_data keys:", risks_data.keys())
    # print("New vulnerabilities count:", len(risks_data.get('new vulnerabilities', [])))
    
    # Print first few new vulnerabilities
    for i, r in enumerate(risks_data.get('new vulnerabilities', [])[:5]):
        print(f"  New risk {i}: {r.get('risk_name')} - {r.get('severity')}")
    print("="*60)

    # 4. Process and Save to Database
    try:
        # Inject context from the database into the AI's output
        report_data = _inject_overview_scan_and_questionnaire(report_data, org, scan_obj)

        with transaction.atomic():
            # Sort the JSON vulnerabilities BEFORE saving to the database
            if "report" in report_data and isinstance(report_data["report"], list) and len(report_data["report"]) > 0:
                readiness_section = report_data["report"][0].get("Risks & Recommendations", {})
                vulnerabilities = readiness_section.get("Vulnerabilities Found", [])
                
                vulnerabilities.sort(key=lambda v: get_severity_weight(v.get("Severity", "")))
                report_data["report"][0]["Risks & Recommendations"]["Vulnerabilities Found"] = vulnerabilities

            # Create the Report
            new_report = Report.objects.create(
                user_created=user,
                organization=org,
                report_name=f"Report - {org.org_name} - {timezone.now().strftime('%Y-%m-%d')}",
                report_text=report_data, 
                completed=timezone.now()
            )

            if scan_obj:
                scan_obj.report = new_report
                scan_obj.status = 'COMPLETE' 
                scan_obj.save(update_fields=['report', 'status'])

            # Create the Risks
            created_risks = []
            for risk_item in risks_data.get('new vulnerabilities', []):
                new_risk = Risk.objects.create(
                    risk_name=risk_item.get('risk_name'),
                    report=new_report, 
                    organization=org,
                    overview=risk_item.get('overview'),
                    recommendations=risk_item.get('recommendations'),
                    severity=risk_item.get('severity'),
                    affected_elements=", ".join(risk_item.get('affected_elements', [])),
                )
                created_risks.append(new_risk)

            ## DEBUG pt 2
            # print("Created risks count:", len(created_risks))

        print(f"--- Successfully saved Report {new_report.pk} and associated risks. ---")

        # 5. Sort the Python list of Risk objects for returning to the frontend
        created_risks.sort(key=lambda r: get_severity_weight(r.severity))

        return new_report, created_risks

    except Organization.DoesNotExist:
        print(f"[ERROR] Organization with ID {organization_id} not found.")
        return None, None
    except Exception as e:
        print(f"[ERROR] Database save failed: {e}")
        if scan_obj:
            scan_obj.status = 'FAILED'
            scan_obj.save(update_fields=['status'])
        return None, None