import json
from typing import Tuple, List, Optional
from django.db import transaction

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

def build_current_risks_dict(organization_id: int) -> dict:
    """
    Fetches existing risks for an organization and formats them 
    into a dictionary that the AI service expects.
    """
    existing_risks = Risk.objects.filter(organization_id=organization_id)
    
    # Format this to match what your ai_generation_service expects for `current_risks`
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

def generate_and_process_report(
    organization_id: int, 
    user_id: int, 
    context_data: str
) -> Tuple[Optional[Report], Optional[List[Risk]]]:
    """
    Acts as the client to gather DB fields, call the AI service, 
    sort the resulting risks by severity, and update the database.
    """
    
    # 1. Setup the inputs for the AI service
    personal_info = {
        "organization_id": organization_id,
        "user_id": user_id
    }
    
    current_risks = build_current_risks_dict(organization_id)

    # 2. Call the AI generation service
    # Note: ai_generation_service creates the Report and Risk objects in the DB
    report, created_risks = ai_generation_service(personal_info, current_risks, context_data)

    if not report or not created_risks:
        print("[ERROR] AI Service failed to generate report or risks.")
        return None, None

    # 3. Sort the Python list of Risk objects (useful for returning to the frontend)
    created_risks.sort(key=lambda r: get_severity_weight(r.severity))

    # 4. Sort the JSON data inside the Report object
    # We must navigate the schema: report -> [0] -> "Risks & Recommendations" -> "Vulnerabilities Found"
    report_json = report.report_text
    
    try:
        if "report" in report_json and isinstance(report_json["report"], list) and len(report_json["report"]) > 0:
            readiness_section = report_json["report"][0].get("Risks & Recommendations", {})
            vulnerabilities = readiness_section.get("Vulnerabilities Found", [])
            
            # Sort the actual JSON array in place
            vulnerabilities.sort(key=lambda v: get_severity_weight(v.get("Severity", "")))
            
            # Re-assign back to ensure it's updated
            report_json["report"][0]["Risks & Recommendations"]["Vulnerabilities Found"] = vulnerabilities
            
            # Update the report text and save the changes to the database
            report.report_text = report_json
            report.save(update_fields=['report_text'])
            print(f"--- Successfully sorted vulnerabilities in Report {report.report_id} ---")

    except Exception as e:
        print(f"[WARNING] Could not sort JSON vulnerabilities: {e}")

    return report, created_risks