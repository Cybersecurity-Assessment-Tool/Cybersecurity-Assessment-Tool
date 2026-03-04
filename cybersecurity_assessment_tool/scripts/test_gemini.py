from api.services.gemini_client import call_gemini_json


def run(*args):
    """
    Usage:
        python manage.py runscript test_gemini
        python manage.py runscript test_gemini --script-args "Your prompt here"
    """

    prompt = args[0] if args else (
        "Assess a company that has no MFA and reuses admin passwords."
    )

    print("\nCalling Gemini...\n")

    result = call_gemini_json(prompt)

    print("Response:\n")
    print(result)
