import json
import logging
import os
import sys
import google.generativeai as genai
from django.conf import settings
from ..models import Report, Risk

logger = logging.getLogger(__name__)

try: 
    API_KEY = os.environ["GEMINI_API_KEY"]
    genai.configure(api_key=API_KEY)
except KeyError:
    sys.stderr.write("Error: GEMINI_API_KEY not found in environment variables. Please set it.\n")
    # Using placeholder will allow initalization, but calls will fail until user provides a real key.
    genai.configure(api_key="placeholder_key")

MODEL_NAME = 'gemini-2.5-flash'

def sanitize_report_json(report_data: dict, keys_to_remove: list = None) -> dict:
    """
    Recursively searches through the report JSON and removes specific keys 
    that contain PII before sending the context to Gemini.
    """
    if keys_to_remove is None:
        keys_to_remove = ["Overview", "Questionnaire Review"]

    if not isinstance(report_data, (dict, list)):
        return report_data

    if isinstance(report_data, list):
        return [sanitize_report_json(item, keys_to_remove) for item in report_data]

    sanitized_dict = {}
    for key, value in report_data.items():
        if key in keys_to_remove:
            continue # Skip adding this key, effectively removing it
        sanitized_dict[key] = sanitize_report_json(value, keys_to_remove)
        
    return sanitized_dict

def get_gemini_response(user_prompt: str, context_instance=None) -> str:
    """
    Takes a user prompt, detects if context is a Report or Risk, 
    sanitizes PII if necessary, and calls Gemini.
    """
    context_string = ""

    # Handle Report instances
    if isinstance(context_instance, Report):
        try:
            # report_text is an EncryptedJSONField, so it should load as a dict/list natively in Django
            raw_report_data = context_instance.report_text 
            
            # Sanitize the report data
            clean_report_data = sanitize_report_json(raw_report_data)
            
            context_string = f"\n\nContext (Cybersecurity Report):\n{json.dumps(clean_report_data, indent=2)}"
        except Exception as e:
            logger.error(f"Error processing Report context: {e}")
            context_string = "\n\n[Error loading report context]"

    # Handle Risk instances
    elif isinstance(context_instance, Risk):
        # Risks don't contain PII, so we can format them directly
        context_string = (
            f"\n\nContext (Cybersecurity Risk):\n"
            f"Risk Name: {context_instance.risk_name}\n"
            f"Severity: {context_instance.severity}\n"
            f"Overview: {context_instance.overview}\n"
            f"Affected Elements: {context_instance.affected_elements}\n"
            f"Recommendations: {json.dumps(context_instance.recommendations, indent=2)}"
        )

    # Combine the user prompt with the sanitized context
    final_prompt = f"{user_prompt}{context_string}"

    try:
        # Initialize the Gemini model
        model = genai.GenerativeModel(model_name=MODEL_NAME)
        
        # Generate the response
        response = model.generate_content(final_prompt)
        return response.text

    except Exception as e:
        logger.error(f"Error calling Gemini API: {e}")
        return "I'm sorry, I encountered an error while trying to generate a response. Please try again later."
    
def generate_chat_reply_report(report_id, user_message):
    from ..models import Report
    report = Report.objects.get(pk=report_id)
    return get_gemini_response(user_prompt=user_message, context_instance=report)

def generate_chat_reply_risk(risk_id, user_message):
    from ..models import Risk
    risk = Risk.objects.get(pk=risk_id)
    return get_gemini_response(user_prompt=user_message, context_instance=risk)