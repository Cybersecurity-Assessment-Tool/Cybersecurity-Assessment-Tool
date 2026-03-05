import json
# Update this import path if gemini_client is located elsewhere in your app structure
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
    organization_id = "68e1d320-1fe3-4f14-8d1f-760e9dc1da82" 
    user_id = "58f961f8-a5e9-4e58-9efb-8b066abd9f28"
    
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