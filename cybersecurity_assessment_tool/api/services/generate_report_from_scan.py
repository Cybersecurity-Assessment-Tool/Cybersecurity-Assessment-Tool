# api/services/generate_report_from_scan.py

import json
import logging
from django.utils import timezone
from django.db import transaction

# Import your existing, accurate client logic
from .gemini_client import generate_and_process_report

logger = logging.getLogger(__name__)

def generate_report_from_scan(scan_id: str):
    """
    Django-Q2 background task that bridges the Network Scanner with the AI Pipeline.
    """
    # Local import to prevent circular dependencies with models
    from api.models import Scan

    try:
        # 1. Fetch Scan and related data
        scan = Scan.objects.select_related('user', 'organization').get(id=scan_id)
        
        # 2. Prepare the technical context for the AI
        # We combine the raw findings with the network metadata found in the Scan model
        raw_data = json.loads(scan.raw_findings_json or '{}')
        findings = raw_data.get('findings', [])
        
        ai_context = _build_integrated_context(scan, findings)

        # 3. Use your established gemini_client logic
        # This handles the AI call, schema validation, and Report/Risk DB creation
        new_report, created_risks = generate_and_process_report(
            organization_id=scan.organization.organization_id,
            user_id=scan.user.user_id if scan.user else None,
            context_data=ai_context,
            scan_obj=scan ## NEW
        )

        if not new_report:
            raise RuntimeError("AI Service failed to produce a report.")

        # 4. Finalize the Scan record
        with transaction.atomic():
            scan.status = "COMPLETE" # Matches Scan.Status.COMPLETE
            scan.report_completed_at = timezone.now()
            scan.save(update_fields=['report', 'status', 'report_completed_at'])

            # 5. Security: Purge raw findings now that the AI report is saved
            scan.purge_raw_findings()

        logger.info(f"Scan {scan_id} successfully processed. Report ID: {new_report.pk}")
        
        return {
            'success': True,
            'report_id': str(new_report.pk),
            'risk_count': len(created_risks)
        }

    except Exception as e:
        logger.exception(f"Processing failed for scan {scan_id}: {e}")
        try:
            # Mark scan as failed in the DB
            from api.models import Scan
            Scan.objects.filter(id=scan_id).update(status="FAILED", error_message=str(e))
        except:
            pass
        return {'success': False, 'error': str(e)}

def _build_integrated_context(scan, findings: list) -> str:
    """
    Format network metadata and findings into a single string for the AI.
    """
    metadata = {
        "Scan Date": scan.scan_completed_at.isoformat() if scan.scan_completed_at else "N/A",
        "Scan Duration": f"{scan.scan_duration_seconds}s",
        "Tools Skipped": scan.skipped_tools,
        "Groups Completed": f"{scan.groups_completed}/15",
        "Finding Counts": {
            "Critical": scan.finding_count_critical,
            "High": scan.finding_count_high,
            "Medium": scan.finding_count_medium,
            "Low": scan.finding_count_low,
            "Info": scan.finding_count_info,
        }
    }

    context_blocks = [
        "--- NETWORK SCAN METADATA ---",
        json.dumps(metadata, indent=2),
        "\n--- DETAILED FINDINGS ---",
        json.dumps(findings, indent=2)
    ]
    
    return "\n".join(context_blocks)