import json
from api.services.ai_generation_service import ai_generation_service

def run(*args):
    """
    Usage:
        python manage.py runscript test_gemini
        python manage.py runscript test_gemini --script-args "Your prompt here"
    """

    # 1. Context is the raw technical data/prompt you want Gemini to analyze.
    # We grab it from args if provided, otherwise use a default test string.
    context = args[0] if args else (
        "Assess a company that has no MFA, reuses admin passwords, "
        "has port 3389 open to the internet, and lacks DMARC records."
    )
    
    # 2. personal_info needs to be a dict with IDs that exist in your local database!
    # UPDATE THESE IDs to match a valid Organization and User in your DB.
    personal_info = {
        "organization_id": "68e1d320-1fe3-4f14-8d1f-760e9dc1da82", 
        "user_id": "58f961f8-a5e9-4e58-9efb-8b066abd9f28"
    }
    
    # 3. current_risks simulates the existing risks the org already knows about.
    # This gives Gemini something to cross-reference against to avoid duplicates.
    current_risks = {
        "known_vulnerabilities": [
            {
                "risk_name": "Lack of DMARC",
                "overview": "Domain is missing DMARC record, allowing email spoofing.",
                "severity": "Medium",
                "affected_elements": ["email domain"],
                "recommendations": {
                    "easy_fix": "Add a basic p=none DMARC record.",
                    "long_term_fix": "Enforce p=reject."
                }
            }
        ]
    }

    print(f"\n--- Calling Gemini with context ---\n{context}\n")

    # ai_generation_service returns a tuple: (Report object, list of Risk objects)
    report, risks = ai_generation_service(personal_info, current_risks, context)

    print("\n--- Generation Complete ---\n")
    
    if report:
        print(f"✅ Report Created: {report.report_name} (ID: {report.pk})")
        print("\nReport JSON excerpt:")
        print(json.dumps(report.report_text, indent=2) + "\n...\n")
    else:
        print("❌ Report generation failed or returned None.")

    if risks:
        print(f"✅ Created {len(risks)} new risks:")
        for r in risks:
            print(f"  - [{r.severity}] {r.risk_name}")
    else:
        print("ℹ️ No new risks were created (or risk generation failed).")