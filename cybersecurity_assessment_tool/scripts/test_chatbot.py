import json
from api.services import chatbot_client

# --- MOCK MODELS ---
class MockRisk:
    risk_name = "Unauthenticated SQL Injection"
    severity = "Critical"
    overview = "An attacker can inject arbitrary SQL queries into the login endpoint."
    affected_elements = "https://example.com/api/v1/login, auth_controller.py"
    recommendations = {
        "easy_fix": "Implement parameterized queries using the Django ORM.",
        "long_term_fix": "Conduct a full code review of all endpoints interacting with the database."
    }

class MockReport:
    report_name = "Q3 Penetration Test"
    report_text = {
        "report": [
            {
                "Overview": "ACME Corp suffers from legacy endpoint vulnerabilities. Jane Doe (Admin) was successfully phished.",
                "Questionnaire Review": "MFA is disabled. This exposes the organization to account takeovers.",
                "Observations": [
                    {
                        "Observation": "Good password policy", 
                        "Overview": "Passwords are enforced at 14+ characters."
                    }
                ],
                "Conclusion": "Jane Doe's workstation is compromised. Needs immediate remediation."
            }
        ]
    }

# --- THE ACTUAL TEST LOGIC ---
def execute_test(user_prompt, context_instance):
    print("\n" + "="*60)
    print(f"STEP 1: PRE-CHECK & CONTEXT ({type(context_instance).__name__})")
    print("="*60)
    print(f"User Prompt: '{user_prompt}'\n")

    if isinstance(context_instance, MockReport):
        print("--- RAW DATA (Contains PII in 'Overview' and 'Questionnaire Review') ---")
        print(json.dumps(context_instance.report_text, indent=2))
        
        clean_data = chatbot_client.sanitize_report_json(context_instance.report_text)
        print("\n--- SANITIZED DATA (PII Scrubbed) ---")
        print(json.dumps(clean_data, indent=2))

    print("\n" + "="*60)
    print("STEP 2: SENDING TO GEMINI API via chatbot_client.py")
    print("="*60)
    print("Calling get_gemini_response()...")
    
    bot_reply = chatbot_client.get_gemini_response(
        user_prompt=user_prompt, 
        context_instance=context_instance
    )

    print("\n" + "="*60)
    print("STEP 3: GEMINI RESPONSE")
    print("="*60)
    print(bot_reply)
    print("="*60 + "\n")

# --- THE RUNSCRIPT ENTRY POINT ---
def run(*args):
    """
    This is the function that 'python manage.py runscript test_chatbot' will execute.
    """
    # Monkey-patching the client so it accepts our mocks
    chatbot_client.Risk = MockRisk
    chatbot_client.Report = MockReport

    print("Starting Chatbot Client Tests via runscript...\n")
    
    # Test 1: Ask about a specific Risk
    risk_instance = MockRisk()
    execute_test("Can you explain the easy fix for this in simpler terms?", risk_instance)

    # Test 2: Ask about a Report
    report_instance = MockReport()
    execute_test("What observations were made in this report?", report_instance)