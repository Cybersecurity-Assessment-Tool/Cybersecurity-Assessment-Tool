import json
import logging
from django.core.cache import cache
from django.core.paginator import Paginator
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django_q.tasks import async_task

from .models import Scan, ScanToken, Risk
# Import the new orchestrator service
from .services.generate_report_from_scan import generate_report_from_scan

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Generate scan token
#    Called when user clicks "Download Scanner" on the scan page.
#    Returns a token the user will paste into the exe GUI.
# ---------------------------------------------------------------------------

@login_required
@require_POST
def generate_scan_token(request):
    """
    Generates a one-time scan token tied to the requesting user + organization.
    Invalidates any previously unused tokens for this user to prevent accumulation.
    """
    user = request.user

    # Validate user has an organization
    if not hasattr(user, 'organization') or not user.organization:
        return JsonResponse(
            {'error': 'No organization associated with your account.'},
            status=400
        )
        
    if not user.organization.questionnaire_completed:
        return JsonResponse(
            {'error': 'Organization security questionnaire must be completed before scanning.'},
            status=403 # 403 Forbidden since they lack the prerequisite to use this resource
        )

    # Expire any existing unused tokens for this user
    ScanToken.objects.filter(
        user=user,
        is_used=False,
        expires_at__gt=timezone.now()
    ).update(expires_at=timezone.now())  # expire immediately

    # Create a new token
    token = ScanToken.objects.create(
        user=user,
        organization=user.organization,
    )

    # Create a PENDING scan record tied to this token
    scan = Scan.objects.create(
        user=user,
        organization=user.organization,
        token=token,
        status=Scan.Status.PENDING,
    )

    return JsonResponse({
        'token': str(token.token),
        'scan_id': str(scan.id),
        'expires_at': token.expires_at.isoformat(),
        'submit_url': request.build_absolute_uri('/api/scan/submit/'),
    }, status=201)


# ---------------------------------------------------------------------------
# 2. Submit scan results
#    Called by the exe after scanning completes.
#    Validates token, stores results, triggers Gemini report generation.
# ---------------------------------------------------------------------------

@csrf_exempt   # exe cannot carry a CSRF cookie - we use token auth instead
@require_POST
def submit_scan_results(request):
    """
    Receives the completed scan JSON from the client-side exe.
    Authenticates via the one-time ScanToken (passed in Authorization header).
    """

    # -- Authenticate via ScanToken header --
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('ScanToken '):
        return JsonResponse({'error': 'Missing or invalid Authorization header.'}, status=401)

    token_value = auth_header.split(' ', 1)[1].strip()

    try:
        token_obj = ScanToken.objects.select_related('user', 'organization').get(token=token_value)
    except (ScanToken.DoesNotExist, ValueError):
        return JsonResponse({'error': 'Invalid token.'}, status=401)

    if not token_obj.is_valid:
        return JsonResponse({'error': 'Token has expired or already been used.'}, status=401)

    # -- Parse body --
    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON body.'}, status=400)

    findings = body.get('findings', [])
    raw_results = body.get('raw_results', {})

    # -- DEBUG LOGGING --
    # print("="*60)
    # print("SUBMIT_SCAN_RESULTS: Received findings count:", len(findings))
    # if findings:
    #     # Print first few findings for inspection
    #     for i, f in enumerate(findings[:5]):
    #         print(f"Finding {i}: severity={f.get('severity')}, description={f.get('description', '')[:50]}")
    # print("="*60)

    # -- Retrieve the associated Scan record --
    try:
        scan = Scan.objects.get(token=token_obj)
    except Scan.DoesNotExist:
        return JsonResponse({'error': 'No scan record associated with this token.'}, status=404)

    # -- Populate scan record --
    scan.status = Scan.Status.RECEIVED
    scan.target_subnet = body.get('target_subnet', '')
    scan.scanner_version = body.get('scan_version', '')
    scan.scan_duration_seconds = body.get('scan_duration_seconds')
    scan.groups_completed = body.get('groups_completed', 0)
    scan.skipped_tools = body.get('skipped_tools', [])
    scan.scan_completed_at = timezone.now()

    # Store findings (encrypted via EncryptedTextField in models_scan.py)
    all_results = {
        'findings': findings,
        'raw_results': raw_results,
    }
    scan.set_findings(findings)
    scan.tally_findings(findings)

    # DEBUG pt 2
    # print("After tally_findings:", 
    #     f"crit={scan.finding_count_critical}, high={scan.finding_count_high}, "
    #     f"med={scan.finding_count_medium}, low={scan.finding_count_low}, info={scan.finding_count_info}")

    # Temporarily store full raw results for Gemini
    scan.raw_findings_json = json.dumps(all_results)
    scan.save()

    # -- Consume the token --
    token_obj.consume()

    # -- Queue Gemini report generation via Django-Q2 --
    # We now call the imported function directly for better reliability
    task_id = async_task(
        generate_report_from_scan,
        str(scan.id)
    )

    # Update status to GENERATING so the UI shows the AI is working
    scan.status = Scan.Status.GENERATING
    scan.report_task_id = task_id
    scan.save(update_fields=['status', 'report_task_id'])

    logger.info(f"Scan {scan.id} results received. Report task queued: {task_id}")

    return JsonResponse({
        'status': 'received',
        'scan_id': str(scan.id),
        'message': 'Results received. Report generation queued.',
    }, status=202)


# ---------------------------------------------------------------------------
# 3. Scan status polling
#    Called by the scan page every few seconds to check progress.
# ---------------------------------------------------------------------------

@login_required
@require_GET
def scan_status(request, scan_id):
    """
    Returns the current status of a scan.
    Users can only query their own scans.
    """
    try:
        scan = Scan.objects.select_related('report').get(
            id=scan_id,
            user=request.user,   # enforces ownership
        )
    except Scan.DoesNotExist:
        return JsonResponse({'error': 'Scan not found.'}, status=404)

    response = {
        'scan_id': str(scan.id),
        'status': scan.status,
        'created_at': scan.created_at.isoformat(),
    }

    # Add progress data while scan is running
    if scan.status == Scan.Status.RUNNING and scan.scan_progress:
        response['scan_progress'] = scan.scan_progress

    # Add findings summary once results are received
    if scan.status in [Scan.Status.RECEIVED, Scan.Status.GENERATING, Scan.Status.COMPLETE]:
        response['findings_summary'] = {
            'critical': scan.finding_count_critical,
            'high': scan.finding_count_high,
            'medium': scan.finding_count_medium,
            'low': scan.finding_count_low,
            'info': scan.finding_count_info,
            'total': scan.total_findings,
        }
        response['groups_completed'] = scan.groups_completed
        response['scan_duration_seconds'] = scan.scan_duration_seconds

    # ─── THE STREAMING >:D ──────────────────────────────────────────────
    if scan.status == Scan.Status.GENERATING:
        # 1. Read the dictionary we saved to the cache in run_network_scan
        progress_data = cache.get(f"scan_progress_{scan_id}", {})
        
        # 2. Inject the progress values into the JSON response for the frontend
        response['generation_progress'] = progress_data.get('progress', 5)
        response['generation_text'] = progress_data.get('text', 'Initializing AI...')

        live_risk_counts = cache.get(f"scan_live_risks_{scan_id}", {
            'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0
        })
        response['live_risk_counts'] = live_risk_counts

    # ─── COMPLETE STATE ──────────────────────────────────────────────────
    elif scan.status == Scan.Status.COMPLETE:
        if scan.report_id:
            response['report_id'] = str(scan.report.report_id)
            response['report_url'] = f'/reports/{scan.report.report_id}/'

    # ─── ERROR STATE ─────────────────────────────────────────────────────
    elif scan.status == Scan.Status.FAILED:
        response['error'] = scan.error_message or "An unknown error occurred during the scan."

    return JsonResponse(response)


# ---------------------------------------------------------------------------
# 4. List scans for the scan page using Pagination
#    Returns recent scans for the logged-in user.
# ---------------------------------------------------------------------------

@login_required
@require_GET
def list_scans(request):
    """
    Returns a paginated list of scans for the logged-in user (10 per page).
    Accepts:  ?page=N   (defaults to 1)
    Returns:
        scans       — list of scan dicts for the requested page
        pagination  — current_page, total_pages, has_previous, has_next,
                      previous_page, next_page
    """
    all_scans = Scan.objects.filter(user=request.user).order_by('-created_at')
    paginator = Paginator(all_scans, 10)
    page_obj  = paginator.get_page(request.GET.get('page', 1))

    scans = [
        {
            'scan_id':                str(s.id),
            'status':                 s.status,
            'created_at':             s.created_at.isoformat(),
            'total_findings':         s.total_findings,
            'finding_count_critical': s.finding_count_critical,
            'finding_count_high':     s.finding_count_high,
            'finding_count_medium':   s.finding_count_medium,
            'finding_count_low':      s.finding_count_low,
            'finding_count_info':     s.finding_count_info,
            'report_id':              str(s.report.report_id) if s.report else None,
        }
        for s in page_obj
    ]

    return JsonResponse({
        'scans': scans,
        'pagination': {
            'current_page':  page_obj.number,
            'total_pages':   paginator.num_pages,
            'has_previous':  page_obj.has_previous(),
            'has_next':      page_obj.has_next(),
            'previous_page': page_obj.previous_page_number() if page_obj.has_previous() else None,
            'next_page':     page_obj.next_page_number()     if page_obj.has_next()     else None,
        },
    })


# ---------------------------------------------------------------------------
# 5. Start server-side scan
#    Called by the "Start New Scan" button on the reports page.
#    Runs port scan, email scan, and infra scan entirely on the server,
#    then generates an AI report and emails the user when done.
# ---------------------------------------------------------------------------

@login_required
@require_POST
def start_server_scan(request):
    """
    Creates a Scan record and queues run_network_scan as a Django-Q2 background task.
    Targets are read from the organization's saved configuration.
    """
    user = request.user

    if not user.organization:
        return JsonResponse(
            {'error': 'No organization associated with your account.'},
            status=400
        )

    if not user.organization.questionnaire_completed:
        return JsonResponse(
            {'error': 'Complete the security questionnaire before scanning. '
                      'Go to Settings → Security Posture.'},
            status=403
        )

    if not user.organization.external_ip:
        return JsonResponse(
            {'error': 'No external IP configured. '
                      'Add it in Settings → Security Posture.'},
            status=400
        )

    email_domains = [d.strip() for d in (user.organization.email_domain or '').split(',') if d.strip()]
    if not email_domains:
        return JsonResponse(
            {'error': 'No email domain configured. '
                      'Add it in Settings → Security Posture.'},
            status=400
        )
    
    # Parse the scan types from the request body
    try:
        data = json.loads(request.body)
        scan_arr = data.get('scan_types', [1, 1, 1, 1]) # fallback
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({'error': 'Invalid scan configuration.'}, status=400)

    # Create the scan record (no ScanToken needed for server-side scans)
    scan = Scan.objects.create(
        user=user,
        organization=user.organization,
        status=Scan.Status.PENDING,
        scan_types_run=scan_arr,
    )

    # Queue the background task (timeout 900s = 15 min to allow for scan + Gemini report generation)
    task_id = async_task(
        'api.services.network_scan.run_network_scan',
        str(scan.id),
        scan_arr,
        timeout=900,
    )

    scan.report_task_id = task_id
    scan.save(update_fields=['report_task_id'])

    logger.info(f"Server scan {scan.id} queued as task {task_id} for user {user.username}")

    return JsonResponse({
        'status': 'started',
        'scan_id': str(scan.id),
        'message': "Scan started. We'll email you when your report is ready — this usually takes 3-5 minutes.",
    }, status=202)

# ---------------------------------------------------------------------------
#  Retry Scan Button
# ---------------------------------------------------------------------------

@login_required
@require_POST
def retry_scan_generation(request, scan_id):
    """
    Restarts the scan or AI generation depending on where it failed.
    """
    try:
        # Fetch the scan and ensure the requesting user owns it
        scan = Scan.objects.get(id=scan_id, user=request.user)
    except Scan.DoesNotExist:
        return JsonResponse({'error': 'Scan not found or unauthorized.'}, status=404)

    if scan.status != "FAILED":
        return JsonResponse({'error': 'Only failed scans can be retried.'}, status=400)

    # Clear the previous error message
    scan.error_message = None

    # Condition: Did the network scan finish successfully?
    if scan.raw_findings_json:
        # YES: We have scan data, so only the AI generation failed.
        # scan.status = "RECEIVED" 
        # scan.save(update_fields=['status', 'error_message'])

        # Re-queue just the AI task
        task_id = async_task('api.services.generate_report_from_scan.generate_report_from_scan', scan_id=str(scan.id))
        
        # Update status to GENERATING instead of RECEIVED to show that the AI is processing the report
        scan.status = "GENERATING" 
        scan.report_task_id = task_id # give a new task ID since this is a new generation
        scan.save(update_fields=['status', 'error_message', 'report_task_id'])
        
        msg = 'AI generation restarted.'
        
    else:
        # NO: We have no scan data, the network scanner itself failed.
        scan.status = "PENDING"
        scan.save(update_fields=['status', 'error_message'])

        # Re-queue the full network scan task (with the 15-minute timeout)
        async_task(
            'api.services.network_scan.run_network_scan', 
            str(scan.id),
            timeout=900
        )
        msg = 'Network scan restarted.'

    return JsonResponse({'success': True, 'message': msg})