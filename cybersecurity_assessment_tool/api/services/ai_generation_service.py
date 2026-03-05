import json
import os
import sys
from dotenv import load_dotenv, find_dotenv
import google.generativeai as gen
from django.db import transaction
from django.utils import timezone
import jsonschema
from ..models import Report, Risk, Organization, User
from google import genai
from google.genai import types
from typing import Dict, Any
from django.conf import settings

# -----------------------------------------------------------------------------
# MODEL AND API KEY SETUP
# -----------------------------------------------------------------------------

load_dotenv(find_dotenv())

try: 
    API_KEY = os.environ["GEMINI_API_KEY"]
    gen.configure(api_key=API_KEY)
except KeyError:
    sys.stderr.write("Error: GEMINI_API_KEY not found in environment variables. Please set it.\n")
    # Using placeholder will allow initalization, but calls will fail until user provides a real key.
    gen.configure(api_key="placeholder_key")

# Change the model here
MODEL_NAME = 'gemini-2.5-flash'
model = gen.GenerativeModel(model_name=MODEL_NAME, )

# -----------------------------------------------------------------------------
# REPORT SCHEMA
# -----------------------------------------------------------------------------

REPORT_SCHEMA_TYPED = types.Schema(
    type=types.Type.OBJECT,
    properties={
        "report": types.Schema(
            type=types.Type.ARRAY,
            description="A cybersecurity assessment report on an organization's current security risks.",
            items=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "Risks & Recommendations": types.Schema(
                        type=types.Type.OBJECT,
                        description="A paragraph summary of the organization's network and a list of found vulnerabilites.",
                        properties={ 
                            "Summary": types.Schema(
                                type=types.Type.STRING,
                                description="A summary of the organization's network."
                            ),
                            "Vulnerabilities Found": types.Schema(
                                type=types.Type.ARRAY,
                                description="A list of found vulnerabilities.",
                                items=types.Schema( 
                                    type=types.Type.OBJECT,
                                    properties={
                                        "Risk": types.Schema(type=types.Type.STRING, description="A short name of what the risk is."),
                                        "Overview": types.Schema(type=types.Type.STRING, description="A text description of the risk, explaining what it is, its impact, and how it was identified."),
                                        "Severity": types.Schema(type=types.Type.STRING, description="The calculated severity score (Critical, High, Medium, Low, or Info) for the risk."),
                                        "Affected Elements": types.Schema(
                                            type=types.Type.ARRAY,
                                            description="A list of system components, files, URLs, or specific functions/code areas affected by this risk.",
                                            items=types.Schema(type=types.Type.STRING)
                                        ),
                                        "Recommendation": types.Schema(
                                            type=types.Type.OBJECT,
                                            description="Specific recommendations for mitigating each risk in Vulnerabilities Found.",
                                            properties={
                                                "easy_fix": types.Schema(type=types.Type.STRING, description="A quick, immediate, or easy-to-implement mitigation step."),
                                                "long_term_fix": types.Schema(type=types.Type.STRING, description="A more difficult, time-consuming, or comprehensive architectural fix, if necessary.")
                                            }
                                        )
                                    }
                                )
                            )
                        }
                    ),
                    "Observations": types.Schema(
                        type=types.Type.ARRAY, 
                        description="A list of what the organization did well.",
                        items=types.Schema(
                            type=types.Type.OBJECT,
                            properties={
                                "Observation": types.Schema(type=types.Type.STRING, description="A short name of what the observation is."),
                                "Overview": types.Schema(type=types.Type.STRING, description="A text description of the observation, explaining what it is, its impact, and how it was identified."),
                                "Affected Elements": types.Schema(
                                    type=types.Type.ARRAY,
                                    description="A list of system components, files, URLs, or specific functions/code areas involved by this observation.",
                                    items=types.Schema(type=types.Type.STRING)
                                )
                            }
                        )
                    ),
                    "Conclusion": types.Schema(
                        type=types.Type.STRING,
                        description="A summary of the organization's current vulnerabilites and readiness."
                    )
                },
                required=["Risks & Recommendations", "Observations", "Conclusion"]
            )
        )
    },
    required=["report"]
)

REPORT_SCHEMA_JSON: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "report": {
            "type": "array",
            "description": "A cybersecurity assessment report on an organization's current security risks.",
            "items": {
                "type": "object",
                "properties": {
                    "Risks & Recommendations": {
                        "type": "object",
                        "description": "A paragraph summary of the organization's network and a list of found vulnerabilites.",
                        "properties": { # FIXED: Changed 'items' to 'properties'
                            "Summary": {
                                "type": "string",
                                "description": "A summary of the organization's network."
                            },
                            "Vulnerabilities Found": {
                                "type": "array",
                                "description": "A list of found vulnerabilities.",
                                "items": { # FIXED: Added 'items' wrapper
                                    "type": "object",
                                    "properties": {
                                        "Risk": {"type": "string", "description": "A short name of what the risk is."},
                                        "Overview": {"type": "string", "description": "A text description of the risk, explaining what it is, its impact, and how it was identified."},
                                        "Severity": {"type": "string", "description": "The calculated severity score (Critical, High, Medium, Low, or Info) for the risk."},
                                        "Affected Elements": {
                                            "type": "array",
                                            "description": "A list of system components, files, URLs, or specific functions/code areas affected by this risk.",
                                            "items": {"type": "string"}
                                        },
                                        "Recommendation": {
                                            "type": "object",
                                            "description": "Specific recommendations for mitigating each risk in Vulnerabilities Found.",
                                            "properties": {
                                                "easy_fix": {"type": "string", "description": "A quick, immediate, or easy-to-implement mitigation step."},
                                                "long_term_fix": {"type": "string", "description": "A more difficult, time-consuming, or comprehensive architectural fix, if necessary."}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "Observations": {
                        "type": "array", # FIXED: Made an array
                        "description": "A list of what the organization did well.",
                        "items": {
                            "type": "object", # FIXED: Made items objects
                            "properties": {
                                "Observation": {"type": "string", "description": "A short name of what the observation is."},
                                "Overview": {"type": "string", "description": "A text description of the observation, explaining what it is, its impact, and how it was identified."},
                                "Affected Elements": {
                                    "type": "array",
                                    "description": "A list of system components, files, URLs, or specific functions/code areas involved by this observation.",
                                    "items": {"type": "string"}
                                }
                            }
                        }
                    },
                    "Conclusion": {
                        "type": "string",
                        "description": "A summary of the organization's current vulnerabilites and readiness."
                    }
                },
                "required": ["Risks & Recommendations", "Observations", "Conclusion"]
            }
        }
    },
    "required": ["report"]
}

# -----------------------------------------------------------------------------
# RISKS SCHEMA
# -----------------------------------------------------------------------------

_vulnerability_schema = types.Schema(
    type=types.Type.OBJECT,
    properties={
        "risk_name": types.Schema(type=types.Type.STRING, description="A concise, descriptive name for the risk (e.g., 'SQL Injection Vulnerability', 'Outdated Library')."),
        "overview": types.Schema(type=types.Type.STRING, description="A text summary of the risk, explaining what it is, its impact, and how it was identified."),
        "severity": types.Schema(type=types.Type.STRING, description="The calculated severity score (Critical, High, Medium, Low, or Info) for the risk."),
        "affected_elements": types.Schema(
            type=types.Type.ARRAY,
            description="A list of system components, files, URLs, or specific functions/code areas affected by this risk.",
            items=types.Schema(type=types.Type.STRING)
        ),
        "recommendations": types.Schema(
            type=types.Type.OBJECT,
            description="Specific recommendations for mitigating the risk.",
            properties={
                "easy_fix": types.Schema(type=types.Type.STRING, description="A quick, immediate, or easy-to-implement mitigation step."),
                "long_term_fix": types.Schema(type=types.Type.STRING, description="A more difficult, time-consuming, or comprehensive architectural fix, if necessary.")
            }
        )
    },
    required=["risk_name", "overview", "severity", "affected_elements", "recommendations"]
)

RISK_SCHEMA_TYPED = types.Schema(
    type=types.Type.OBJECT,
    properties={
        "new vulnerabilities": types.Schema(
            type=types.Type.ARRAY,
            description="A list of all new identified cybersecurity risks/vulnerabilities from the report.",
            items=_vulnerability_schema
        ),
        "all vulnerabilities": types.Schema(
            type=types.Type.ARRAY,
            description="A list of all cybersecurity risks/vulnerabilities.",
            items=_vulnerability_schema
        )
    },
    required=["new vulnerabilities", "all vulnerabilities"]
)

_vulnerability_json = {
    "type": "object",
    "properties": {
        "risk_name": {"type": "string", "description": "A concise, descriptive name for the risk (e.g., 'SQL Injection Vulnerability', 'Outdated Library')."},
        "overview": {"type": "string", "description": "A text summary of the risk, explaining what it is, its impact, and how it was identified."},
        "severity": {"type": "string", "description": "The calculated severity score (Critical, High, Medium, Low, or Info) for the risk."},
        "affected_elements": {
            "type": "array",
            "description": "A list of system components, files, URLs, or specific functions/code areas affected by this risk.",
            "items": {"type": "string"}
        },
        "recommendations": {
            "type": "object",
            "description": "Specific recommendations for mitigating the risk.",
            "properties": {
                "easy_fix": {"type": "string", "description": "A quick, immediate, or easy-to-implement mitigation step."},
                "long_term_fix": {"type": "string", "description": "A more difficult, time-consuming, or comprehensive architectural fix, if necessary."}
            }
        }
    },
    "required": ["risk_name", "overview", "severity", "affected_elements", "recommendations"]
}

RISK_SCHEMA_JSON: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "new vulnerabilities": {
            "type": "array",
            "description": "A list of all new identified cybersecurity risks/vulnerabilities from the report.",
            "items": _vulnerability_json
        },
        "all vulnerabilities": {
            "type": "array",
            "description": "A list of all cybersecurity risks/vulnerabilities.",
            "items": _vulnerability_json
        }
    },
    "required": ["new vulnerabilities", "all vulnerabilities"]
}

def _create_report_prompt() -> str:
    """
    Creates the report prompt to use for each report generation.
    """
    return f"""You need to always respond in a JSON format. You are an
    expert cybersecurity analyst who generates comprehensive security reports. You are evaluating raw 
    technical data and a questionnaire for an organization. If you do not have enough data to draw a conclusion, simply state you do not know.
    Only output valid JSON. You need to make sure you correlate the Organization Name, Email Domain, 
    and External IP with the technical records (A, NS, MX, TXT, DMARC) and port scans. Every response you generate
    should be in the following JSON format: {{"thought": "you should always
    think about what you need to do"}}.
    Do not end the analysis until the entire dataset has been checked and all conclusions are drawn.
    Pass the formatted vulnerabilities and summaries into the "report" section. 
    Draw conclusions (e.g., p=reject is strong, no open ports is secure) 
    rather than just listing data. Do not include any conversational text or markdown. 
    If the full report has been compiled, end the analysis.
    """

def _create_risk_prompt() -> str:
    """
    Creates the risk prompt to use for each risk list generation.
    """
    return f"""You need to always respond in a JSON format. You are an
    expert cybersecurity analyst who extracts vulnerabilities. You are evaluating a 
    security report for an organization. If you do not have enough data to assess a risk, simply state you do not know.
    Only output valid JSON. You need to make sure you cross-reference every vulnerability
    against the list of existing risks during your analysis. Every response you generate
    should be in the following JSON format: {{"thought": "you should always
    think about what you need to do"}}.
    Do not end the analysis until the entire report vulnerabilities list has been checked.
    The current risk list tells you which risks are already known.
    Each entry corresponds to a vulnerability already tracked by the organization. 
    Pass the new vulnerabilities that are NOT in the known risks list into the "_new_vulnerabilities" section. 
    If you identify multiple new risks in the report then pass all of the new risks as a list into the
    "new_vulnerabilities" section. Assign accurate severities and provide an 'easy_fix' and 'long_term_fix'.
    Process the lists carefully to ensure no duplicates are created.
    Do not include any conversational text or markdown. If all vulnerabilities have been processed, end the
    analysis.
    """

def _create_example(example_input, example_output) -> str:
    """
    Creates an example for the AI to reference as a template.
    """
    try:
        if isinstance(example_input, str):
            with open(example_input, 'r') as f:
                data_in = json.load(f)
        else:
            data_in = example_input

        if isinstance(example_output, str):
            with open(example_output, 'r') as f:
                data_out = json.load(f)
        else:
            data_out = example_output
            
        return f"Example Input:\n{json.dumps(data_in, indent=2)}\n\nExample Output:\n{json.dumps(data_out, indent=2)}"
    except Exception as e:
        print(f"[WARNING] Could not load examples: {e}")
        return "Example context missing or invalid."

def _generate_report_content(context):
    """
    Calls the AI model to generate report content.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    context_path = os.path.join(current_dir, "..", "assets", "report_template", "context.json")
    test_report_path = os.path.join(current_dir, "..", "assets", "report_template", "test_report.json")

    context_path = os.path.normpath(context_path)
    test_report_path = os.path.normpath(test_report_path)

    example = _create_example(context_path, test_report_path)

    print(f"--- Calling Gemini API with model: {MODEL_NAME} ---")
    
    full_prompt = f"{_create_report_prompt()}\n\nContext:\n{context}\n\n{example}"
        
    response = model.generate_content(
        contents=full_prompt,
        generation_config=gen.types.GenerationConfig(
            response_mime_type="application/json",
            response_schema=REPORT_SCHEMA_JSON
        )
    )
        
    if not response.text:
        raise RuntimeError("Empty response from Gemini for report generation.")

    data = json.loads(response.text)
    jsonschema.validate(instance=data, schema=REPORT_SCHEMA_JSON)
            
    print("--- Finished creating and validating report response successfully! ---")
    return data

def _add_risks(report: dict, current_risks: dict):
    """
    Calls the AI model to create new risks based on the JSON formatted report given.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    current_risk_path = os.path.join(current_dir, "..", "assets", "risk_template", "current_risk.json")
    test_risk_path = os.path.join(current_dir, "..", "assets", "risk_template", "test_risk_list.json")

    current_risk_path = os.path.normpath(current_risk_path)
    test_risk_path = os.path.normpath(test_risk_path)

    example = _create_example(current_risk_path, test_risk_path)
    
    extracted_vulnerabilities = []
    if "report" in report and isinstance(report["report"], list) and len(report["report"]) > 0:
        readiness_section = report["report"][0].get("Risks & Recommendations", {})
        extracted_vulnerabilities = readiness_section.get("Vulnerabilities Found", [])

    context = (
        f"Report Vulnerabilities:\n{json.dumps(extracted_vulnerabilities, indent=2)}\n\n"
        f"Current Risks:\n{json.dumps(current_risks, indent=2)}"
    )

    print(f"--- Calling Gemini API with model: {MODEL_NAME} ---")
    
    full_prompt = f"{_create_risk_prompt()}\n\n{context}\n\n{example}"
        
    response = model.generate_content(
        contents=full_prompt,
        generation_config=gen.types.GenerationConfig(
            response_mime_type="application/json",
            response_schema=RISK_SCHEMA_JSON
        )
    )
    
    if not response.text:
        raise RuntimeError("Empty response from Gemini for risk generation.")

    data = json.loads(response.text)
    jsonschema.validate(instance=data, schema=RISK_SCHEMA_JSON)
        
    print("--- Finished creating and validating risk response successfully! ---")
    return data

#TODO: MUST edit this function if the questionnaire changes. 
def _inject_overview_and_questionnaire(report_data: dict, org: Organization) -> dict:
    """
    Injects the Overview and Questionnaire Review sections at the top 
    of the AI-generated report data using information from the database.
    """
    new_section_data = {
        "Overview": {
            "Organization Name": org.org_name,
            "Primary Domain": org.email_domain,
            "External IP Address": org.external_ip,
            "Report Date": timezone.now().strftime('%Y-%m-%d')
        },
        "Questionnaire Review": {
            "Do you require MFA to access email?": "Yes" if org.require_mfa_email else "No",
            "Do you require MFA to log into computers?": "Yes" if org.require_mfa_computer else "No",
            "Do you require MFA to access sensitive data systems?": "Yes" if org.require_mfa_sensitive_data else "No",
            "Does your organization have an employee acceptable use policy?": "Yes" if org.employee_acceptable_use_policy else "No",
            "Does your organization do security awareness training for new employees?": "Yes" if org.training_new_employees else "No",
            "Does your organization do security awareness training for all employees at least once per year?": "Yes" if org.training_once_per_year else "No"
        }
    }

    if "report" in report_data and isinstance(report_data["report"], list):
        for i, report_item in enumerate(report_data["report"]):
            rebuilt_report_item = {}
            
            for key, value in new_section_data.items():
                rebuilt_report_item[key] = value
                
            for key, value in report_item.items():
                rebuilt_report_item[key] = value
                
            report_data["report"][i] = rebuilt_report_item

    return report_data

def ai_generation_service(personal_info: dict, current_risks: dict, context):
    """
    Generates a report and risks using Gemini.
    Returns the created Report object and a list of created Risk objects.
    """
    try:
        # 1. Generate and validate report data
        report_data = _generate_report_content(context)
        
        # 2. Fetch database records
        org = Organization.objects.get(organization_id=personal_info.get('organization_id'))
        user_id = personal_info.get('user_id') 
        user = User.objects.get(user_id=user_id) if user_id else None

        # 3. Inject context
        report_data = _inject_overview_and_questionnaire(report_data, org)

        # 4. Save to database
        with transaction.atomic():
            new_report = Report.objects.create(
                user_created=user,
                organization=org,
                report_name=f"Report - {org.org_name} - {timezone.now().strftime('%Y-%m-%d')}",
                report_text=report_data, 
                completed=timezone.now()
            )

            # 5. Generate and validate risks data
            risks_data = _add_risks(report_data, current_risks)

            created_risks = []
            for risk_item in risks_data.get('new vulnerabilities', []):
                new_risk = Risk.objects.create(
                    risk_name=risk_item.get('risk_name'),
                    report=new_report, 
                    organization=org,
                    overview=risk_item.get('overview'),
                    recommendations=risk_item.get('recommendations'),
                    severity=risk_item.get('severity'),
                    affected_elements=", ".join(risk_item.get('affected_elements', [])),
                )
                created_risks.append(new_risk)
        
            print(f"--- Successfully saved Report {new_report.report_id} and associated risks. ---")
            return new_report, created_risks

    except jsonschema.ValidationError as e:
        print(f"[ERROR] AI output did not match required schema: {e.message}")
    except Organization.DoesNotExist:
        print(f"[ERROR] Organization with ID {personal_info.get('organization_id')} not found.")
    except User.DoesNotExist:
        print(f"[ERROR] User with ID {personal_info.get('user_id')} not found.")
    except Exception as e:
        print(f"[ERROR] Pipeline failed: {e}")
        
    return None, None