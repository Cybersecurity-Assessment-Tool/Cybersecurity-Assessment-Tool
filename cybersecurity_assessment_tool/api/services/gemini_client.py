import json
from typing import Any, Tuple, List, Optional
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache

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
            "Does your organization do security awareness training for all employees at least once per year?": "Yes" if org.training_once_per_year else "No",
            "Does your organization regularly change/rotate your admin passwords?": "Yes" if org.admin_rotate else "No"
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

def _build_scan_findings(scan_obj: Any) -> dict:
    """
    Builds a structured 'Scan Findings' dict from the Scan model instance.
    """
    if not scan_obj or not hasattr(scan_obj, 'finding_count_critical'):
        return {}

    result = {
        'duration_seconds': getattr(scan_obj, 'scan_duration_seconds', None),
        'scanner_version': getattr(scan_obj, 'scanner_version', '') or '',
        'groups_completed': getattr(scan_obj, 'groups_completed', 0),
        'counts': {
            'Critical': getattr(scan_obj, 'finding_count_critical', 0),
            'High': getattr(scan_obj, 'finding_count_high', 0),
            'Medium': getattr(scan_obj, 'finding_count_medium', 0),
            'Low': getattr(scan_obj, 'finding_count_low', 0),
            'Info': getattr(scan_obj, 'finding_count_info', 0),
        },
    }

    # Capture individual findings before they are purged.
    try:
        raw = scan_obj.raw_findings_json
        if raw:
            container = json.loads(raw) if isinstance(raw, str) else raw
            all_findings = container.get('findings', []) if isinstance(container, dict) else []

            # Keep only port-based findings (tcp/udp) that have a port ID.
            port_findings = [
                {
                    'severity': f.get('severity', 'INFO'),
                    'portid': f.get('portid', ''),
                    'protocol': f.get('protocol', ''),
                    'service': f.get('service', ''),
                    'description': f.get('description', ''),
                    'information': f.get('information', ''),
                }
                for f in all_findings
                if f.get('scan_type') in ('tcp', 'udp') and f.get('portid')
            ]

            # Sort by severity so Critical findings appear first in the table.
            sev_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'INFO': 5}
            port_findings.sort(key=lambda f: sev_order.get(f['severity'].upper(), 6))

            result['findings'] = port_findings
    except Exception:
        pass

    return result

def _inject_overview_scan_and_questionnaire(report_data: dict, org: Organization, scan_obj: Any = None) -> dict:
    """
    Injects the Overview, Scan Findings, and Questionnaire Review sections at the top 
    of the AI-generated report data using information from the database.
    """
    scan_findings = _build_scan_findings(scan_obj)
    
    new_sections = {
        "Overview": {
            "Organization Name": org.org_name,
            "Email Domain": org.email_domain,
            "Website Domain": org.website_domain,
            "External IP Address": org.external_ip,
            "Report Date": timezone.now().strftime('%Y-%m-%d')
        },
        "Questionnaire Review": {
            "Do you require MFA to access email?": "Yes" if org.require_mfa_email else "No",
            "Do you require MFA to log into computers?": "Yes" if org.require_mfa_computer else "No",
            "Do you require MFA to access sensitive data systems?": "Yes" if org.require_mfa_sensitive_data else "No",
            "Does your organization have an employee acceptable use policy?": "Yes" if org.employee_acceptable_use_policy else "No",
            "Does your organization do security awareness training for new employees?": "Yes" if org.training_new_employees else "No",
            "Does your organization do security awareness training for all employees at least once per year?": "Yes" if org.training_once_per_year else "No",
            "Does your organization regularly change/rotate your admin passwords?": "Yes" if org.admin_rotate else "No"
        }
    }

    if scan_findings:
        new_sections["Scan Findings"] = scan_findings

    if "report" in report_data and isinstance(report_data["report"], list):
        for i, report_item in enumerate(report_data["report"]):
            rebuilt_report_item = {}
            
            for key, value in new_sections.items():
                rebuilt_report_item[key] = value
                
            for key, value in report_item.items():
                rebuilt_report_item[key] = value
                
            report_data["report"][i] = rebuilt_report_item

    return report_data

def generate_and_process_report(
    organization_id: str, 
    user_id: str, 
    context_data: str,
    scan_obj: Optional[Any] = None,
    chunk_callback=None
) -> Tuple[Optional[Report], Optional[List[Risk]], str]: 
    """
    Gathers DB fields, calls the AI service, injects database context, and saves.
    context_data must be a JSON string (the AI only accepts strings).
    """
    # Fetch the database records
    try:
        org = Organization.objects.get(organization_id=organization_id)
        user = User.objects.get(user_id=user_id) if user_id else None
    except Organization.DoesNotExist:
        return None, None, f"Organization ID {organization_id} not found."
        
    # 1. Fetch current risks
    current_risks = build_current_risks_dict(organization_id)
    
    # 2. Fetch the questionnaire information
    questionnaire = get_questionnaire_dict(org)

    # 3. Call the AI generation service
    report_data, risks_data, ai_error_msg = ai_generation_service(
        questionnaire, 
        current_risks, 
        context_data, 
        chunk_callback=chunk_callback 
    )

    # 4. Check for AI failure
    if not report_data or not risks_data:
        final_error = ai_error_msg or "The AI API failed to return data."
        if scan_obj:
            scan_obj.status = 'FAILED'
            try:
                scan_obj.error_message = final_error
                scan_obj.save(update_fields=['status', 'error_message'])
            except Exception:
                scan_obj.save(update_fields=['status'])
        return None, None, final_error

    # 5. Process and Save to Database
    try:
        # Inject context from the database into the AI's output
        report_data = _inject_overview_scan_and_questionnaire(report_data, org, scan_obj)

        with transaction.atomic():
            # Sort the JSON vulnerabilities BEFORE saving to the database
            if "report" in report_data and isinstance(report_data["report"], list) and report_data["report"]:
                readiness_section = report_data["report"][0].get("Risks & Recommendations", {})
                vulnerabilities = readiness_section.get("Vulnerabilities Found") or []
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

            # Create the Risks
            final_ai_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            created_risks = []
            
            ai_vulnerabilities = risks_data.get('new vulnerabilities') or []
            
            for risk_item in ai_vulnerabilities:
                affected = risk_item.get('affected_elements') or []
                
                new_risk = Risk.objects.create(
                    risk_name=risk_item.get('risk_name') or 'Unknown Risk',
                    report=new_report, 
                    organization=org,
                    overview=risk_item.get('overview') or '',
                    recommendations=risk_item.get('recommendations') or {},
                    severity=risk_item.get('severity') or 'Info',
                    affected_elements=", ".join(affected),
                )
                created_risks.append(new_risk)

                # Add a running tally of risks found to the cache
                if scan_obj:
                    cache_key = f"scan_live_risks_{scan_obj.id}"
                    counts = cache.get(cache_key, {
                        'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0
                    })
                    sev = (new_risk.severity or "Info").capitalize()
                    if sev in counts:
                        counts[sev] += 1
                    cache.set(cache_key, counts, timeout=600)

                sev = (new_risk.severity or "Info").capitalize()
                if sev in final_ai_counts:
                    final_ai_counts[sev] += 1

            if scan_obj:
                cache_key = f"scan_live_risks_{scan_obj.id}"
                scan_obj.finding_count_critical = cache.get(cache_key, { 'Critical': 0 })
                scan_obj.finding_count_high = cache.get(cache_key, { 'High': 0 })
                scan_obj.finding_count_medium = cache.get(cache_key, { 'Medium': 0 })
                scan_obj.finding_count_low = cache.get(cache_key, { 'Low': 0 })
                scan_obj.finding_count_info = cache.get(cache_key, { 'Info': 0 })

                scan_obj.report = report_data["report"]
                scan_obj.status = 'COMPLETE' 

                scan_obj.save(update_fields=[
                    'report', 'status',
                    'finding_count_critical', 'finding_count_high', 
                    'finding_count_medium', 'finding_count_low', 'finding_count_info'
                ])

        print(f"--- Successfully saved Report {new_report.pk} and associated risks. ---")
        
        # 6. Sort the Python list of Risk objects for returning to the frontend
        created_risks.sort(key=lambda r: get_severity_weight(r.severity))

        # clear cache
        if scan_obj:
            cache.delete(f"scan_live_risks_{scan_obj.id}")

        return new_report, created_risks, ""

    except Exception as e:
        db_error = f"Database Processing Error: {str(e)[:400]}"
        if scan_obj:
            scan_obj.status = 'FAILED'
            try:
                scan_obj.error_message = db_error
                scan_obj.save(update_fields=['status', 'error_message'])
            except Exception:
                scan_obj.save(update_fields=['status'])
        return None, None, db_error