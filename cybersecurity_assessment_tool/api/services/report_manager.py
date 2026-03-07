from celery import shared_task
from .gemini_client import generate_and_process_report
#from network_scanner import perform_scan (Change to acutal network scan function)

@shared_task(bind=True)
def generate_network_ai_report(self, target_ip, user_id, organization_id):
    """Background task to scan a network and generate an AI report."""
    # Provide status updates that frontend can read
    #self.update_state(state='PROGRESS', meta={'step': 'Running network scan...'})
    #scan_results = perform_scan(target_ip)
    scan_results = "Assess a company that is doing all network security secure but only has a minor issue with Severity Medium and Severity Info"
    
    # Move to the next phase
    self.update_state(state='PROGRESS', meta={'step': 'Analyzing data with Gemini...'})
    
    # Unpack the tuple
    new_report, created_risks = generate_and_process_report(organization_id, user_id, scan_results)
    
    # Return the final result or the URL to redirect to
    if new_report:
        return {
            'status': 'Completed',
            'report_id': str(new_report.report_id),
            'message': 'Report generated successfully.'
        }
    else:
        return {
            'status': 'Failed',
            'message': 'Report generation failed.'
        }