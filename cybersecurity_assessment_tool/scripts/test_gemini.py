import json
from api.services.gemini_client import generate_and_process_report

def run(*args):
    """
    Usage:
        python manage.py runscript test_gemini
        python manage.py runscript test_gemini --script-args "Your prompt here"
    """

    # 1. Context is the raw technical data/prompt you want Gemini to analyze.
    # We grab it from args if provided, otherwise use a default test string.
    context = args[0] if args else (
        # "Assess a company that has no MFA, reuses admin passwords,"
        # "does not have the port 3389 open to the internet, and does not lack DMARC records."
        "Assess a company that is running an outdated, highly vulnerable FTP server on port 21 "
        "and uses default administrator credentials for their local router."
    )
    
    # 2. UPDATE THESE IDs to match a valid Organization and User in your DB.
    # The client will use these to build the personal_info dict and fetch current_risks.
    organization_id = "6299dc43-e136-48b7-80b1-4331dbecde33" 
    user_id = "7c489eb4-cae1-4a7a-ac8c-7f43453e253a"
    
    print(f"\n--- Calling Gemini Client with context ---\n{context}\n")

    # 3. generate_and_process_report returns a tuple: (Report object, sorted list of Risk objects)
    report, risks = generate_and_process_report(organization_id, user_id, context)

    print("\n--- Generation Complete ---\n")
    
    if report:
        print(f"✅ Report Created: {report.report_name} (ID: {report.pk})")
        print("\nReport JSON excerpt:")
        print(json.dumps(report.report_text, indent=2) + "\n...\n")
    else:
        print("❌ Report generation failed or returned None.")

    if risks:
        print(f"✅ Created {len(risks)} new risks (sorted by severity):")
        for r in risks:
            print(f"  - [{r.severity}] {r.risk_name}")
    else:
        print("ℹ️ No new risks were created (or risk generation failed).")