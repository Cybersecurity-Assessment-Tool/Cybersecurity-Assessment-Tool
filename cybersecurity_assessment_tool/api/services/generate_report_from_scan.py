# api/services/generate_report_from_scan.py

import json
import logging
from django.utils import timezone
from django.db import transaction

# Import your existing, accurate client logic
from .gemini_client import generate_and_process_report

logger = logging.getLogger(__name__)

def generate_report_from_scan(scan_id: str, chunk_callback=None):
    from api.models import Scan
    from django.core.cache import cache

    try:
        scan = Scan.objects.select_related('user', 'organization').get(id=scan_id)
        
        raw_data = json.loads(scan.raw_findings_json or '{}')
        findings = raw_data.get('findings', [])
        
        ai_context = _build_integrated_context(scan, findings)

        # 1. Catch the new 3rd variable (actual_error)
        new_report, created_risks, actual_error = generate_and_process_report(
            organization_id=scan.organization.organization_id,
            user_id=scan.user.user_id if scan.user else None,
            context_data=ai_context,
            scan_obj=scan,
            chunk_callback=chunk_callback
        )

        # 2. Handle AI Failure Gracefully
        if not new_report:
            error_msg = actual_error or "An internal error occurred during report generation."
            logger.error(f"Scan {scan_id} failed: {error_msg}")
            
            # 3. FIX THE FRONTEND: Force the UI to stop spinning!
            cache.set(f"scan_progress_{scan_id}", {
                "progress": 100,
                "text": f"Failed: {error_msg[:50]}..." # Keep it short for UI
            }, timeout=600)
            
            # Save the failure to the DB so the logs look right
            Scan.objects.filter(id=scan_id).update(status="FAILED", error_message=error_msg)
            
            return {'success': False, 'error': error_msg}

        with transaction.atomic():
            scan.status = "COMPLETE" 
            scan.report_completed_at = timezone.now()
            scan.save(update_fields=['report', 'status', 'report_completed_at'])
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
            from api.models import Scan
            from django.core.cache import cache
            
            # Tell the frontend the system crashed
            cache.set(f"scan_progress_{scan_id}", {"progress": 100, "text": "Failed: System Error"}, timeout=600)
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