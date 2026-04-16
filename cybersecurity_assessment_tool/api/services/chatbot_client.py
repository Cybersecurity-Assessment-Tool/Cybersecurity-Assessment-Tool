import json
import google.generativeai as gen
from django.conf import settings
from api.models import Report, Risk

# -----------------------------------------------------------------------------
# MODEL SETUP
# -----------------------------------------------------------------------------

gen.configure(api_key=settings.API_KEY)
MODEL_NAME = 'gemini-2.5-pro'
model = gen.GenerativeModel(model_name=MODEL_NAME)

# -----------------------------------------------------------------------------
# CHATBOT FUNCTIONS (Run asynchronously via Django Q)
# -----------------------------------------------------------------------------

def generate_chat_reply_report(report_id: str, user_message: str) -> str:
    """
    Analyzes a full report and answers a user's question about it.
    Returns a plain text string that Django Q saves to the Task result.
    """
    try:
        report = Report.objects.get(pk=report_id)
        
        # Safely parse the report text if it's stored as a string
        report_data = report.report_text
        if isinstance(report_data, str):
            report_data = json.loads(report_data)
            
        # Format the context
        context = f"Report Name: {report.report_name}\n"
        context += f"Completion Date: {report.completed}\n"
        context += f"Full Report Content: {json.dumps(report_data, indent=2)}\n"
        
        prompt = f"""You are a helpful, expert cybersecurity assistant. 
                    A user is asking a question about their cybersecurity assessment report. 

                    Here is the data from their report:
                    {context}

                    User's Question: {user_message}

                    Instructions:
                    1. Answer the user's question accurately based ONLY on the provided report context.
                    2. Limit your response to a MAXIMUM of ONE paragraph.
                    3. Keep the language extremely simple and easy for non-technical people to understand. Avoid dense IT jargon.
                    4. Do not use markdown formatting like bolding or lists, just return a single conversational paragraph.
                """
        
        response = model.generate_content(prompt)
        
        if not response.text:
            return "I'm sorry, I couldn't generate a response at this time."
            
        return response.text.strip()
        
    except Report.DoesNotExist:
        return "Error: The requested report could not be found."
    except Exception as e:
        print(f"[ERROR] Chatbot report generation failed: {e}")
        return "I'm sorry, I encountered a technical error while analyzing your report."


def generate_chat_reply_risk(risk_id: str, user_message: str) -> str:
    """
    Analyzes a specific vulnerability (Risk) and answers a user's question about it.
    Returns a plain text string that Django Q saves to the Task result.
    """
    try:
        risk = Risk.objects.get(pk=risk_id)
        
        # Format the context
        context = f"Vulnerability Name: {risk.risk_name}\n"
        context += f"Severity: {risk.severity}\n"
        context += f"Overview: {risk.overview}\n"
        context += f"Affected Elements: {risk.affected_elements}\n"
        context += f"Recommendations: {json.dumps(risk.recommendations, indent=2)}\n"
        
        prompt = f"""You are a helpful, expert cybersecurity assistant. 
                    A user is asking a question about a specific security vulnerability (risk) found in their system.

                    Here is the data about this specific vulnerability:
                    {context}

                    User's Question: {user_message}

                    Instructions:
                    1. Answer the user's question accurately based ONLY on the provided vulnerability context.
                    2. Limit your response to a MAXIMUM of ONE paragraph.
                    3. Keep the language extremely simple and easy for non-technical people to understand. Avoid dense IT jargon.
                    4. Do not use markdown formatting like bolding or lists, just return a single conversational paragraph.
                """
        
        response = model.generate_content(prompt)
        
        if not response.text:
            return "I'm sorry, I couldn't generate a response at this time."
            
        return response.text.strip()
        
    except Risk.DoesNotExist:
        return "Error: The requested vulnerability could not be found."
    except Exception as e:
        print(f"[ERROR] Chatbot risk generation failed: {e}")
        return "I'm sorry, I encountered a technical error while analyzing this vulnerability."