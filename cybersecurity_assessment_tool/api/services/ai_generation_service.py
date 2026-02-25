import time
import json
import os
import sys
from dotenv import load_dotenv, find_dotenv
import google.generativeai as genai
from django.db import transaction
from django.utils import timezone
from models import Report, Risk, Organization, User

load_dotenv(find_dotenv())

try: 
    API_KEY = os.environ["GEMINI_API_KEY"]
    genai.configure(api_key=API_KEY)
except KeyError:
    sys.stderr.write("Error: GEMINI_API_KEY not found in environment variables. Please set it.\n")
    # Using placeholder will allow initalization, but calls will fail until user provides a real key.
    genai.configure(api_key="placeholder_key")

# Change the model here
MODEL_NAME = 'gemini-2.5-flash'

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

def _generate_report_content(context_filepath: str, system_instruction: str = "", max_retries=4, delay=2):
    """
    Calls the AI model to generate report content.
    """
    retry_count = 0

    try:
        with open(context_filepath, 'r') as f:
            context_data = f.read()
    except Exception as e:
        print(f"[ERROR] Failed to read context file '{context_filepath}': {e}")
        return None

    example = _create_example(
        "../assets/report_template/context.json", 
        "../assets/report_template/test_report.json"
    )

    model = genai.GenerativeModel(
        model_name=MODEL_NAME, 
        system_instruction=system_instruction
    )

    while retry_count < max_retries:
        print(f"--- Calling Gemini API with model: {MODEL_NAME} (Attempt {retry_count + 1}/{max_retries}) ---")
        
        try:
            response = model.generate_content(
                contents=[_create_report_prompt(), context_data + "\n\n" + example],
                generation_config={
                    'response_mime_type': 'application/json',
                    'response_schema': {
                        "type": "object",
                        "properties": {
                            "report": {
                                "type": "array",
                                "description": "A cybersecurity assessment report on an organization's current security risks.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "Risk Assessment & Readiness": {
                                            "type": "object",
                                            "description": "A paragraph summary of the organization's network and a list of found vulnerabilites.",
                                            "items": {
                                                "Summary": {
                                                    "type": "string",
                                                    "description": "A summary of the organization's network."
                                                },
                                                "Vulnerabilites Found": {
                                                    "type": "object",
                                                    "description": "A list of found vulnerabilities.",
                                                    "properties": {
                                                        "Risk": {
                                                            "type": "string",
                                                            "description": "A short name of what the risk is."
                                                        },
                                                        "Overview": {
                                                            "type": "string",
                                                            "description": "A text description of the risk, explaining what it is, its impact, and how it was identified."
                                                        },
                                                        "Severity": {
                                                            "type": "string",
                                                            "description": "The calculated severity score (Critical, High, Medium, Low, or Info) for the risk."
                                                        },
                                                        "Affected Elements": {
                                                            "type": "array",
                                                            "description": "A list of system components, files, URLs, or specific functions/code areas affected by this risk.",
                                                            "items": {
                                                                "type": "string"
                                                            }
                                                        },
                                                    }
                                                },
                                            }
                                        }, 
                                        "Recommendations": {
                                            "type": "object",
                                            "description": "Specific recommendations for mitigating each risk in Vulnerabilities Found.",
                                            "properties": {
                                                "type": "string"
                                            }
                                        },
                                        "Conclusion": {
                                            "type": "string",
                                            "description": "A summary of the organization's current vulnerabilites and readiness."
                                        },
                                        "required": [
                                            "Risk Assessment & Readiness",
                                            "Recommendations",
                                            "Conclusion"
                                        ]
                                    }
                                }
                            },
                        },
                        "required": ["report"]
                    }
                }
            )

            if not response.text:
                print(f"[WARNING] Empty response text on attempt {retry_count + 1}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

            try: 
                json_data = json.loads(response.text)
                print(f"--- Finished creating response successfully on attempt {retry_count + 1}! ---")
                return response.text
            
            except json.JSONDecodeError as e:
                print(f"[ERROR in generate_report_content] Response text is not valid JSON on attempt {retry_count + 1}. Error: {e}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

        except Exception as e:
            print(f"[ERROR in generate_report_content] API call failed on attempt {retry_count + 1}: {e}. Retrying in {delay} seconds...")
            retry_count += 1
            time.sleep(delay)
            continue

    print(f"--- FAILED to generate report content after {max_retries} attempts. ---")
    return None

def _add_risks(report: dict, current_risks: dict, max_retries=4, delay=2):
    """
    Calls the AI model to add the new risks to the database based on the JSON formatted report given.
    """
    retry_count = 0
    
    example = _create_example(
        "../assets/risk_template/current_risk.json",
        "../assets/risk_template/test_risk_list.json"
    )
    
    # Drill down into the report dictionary to extract only the vulnerabilities
    extracted_vulnerabilities = []
    try:
        # Check if 'report' exists and is a list with at least one item
        if "report" in report and isinstance(report["report"], list) and len(report["report"]) > 0:
            readiness_section = report["report"][0].get("Risk Assessment & Readiness", {})
            extracted_vulnerabilities = readiness_section.get("Vulnerabilities Found", [])
    except Exception as e:
        print(f"[WARNING] Could not parse vulnerabilities from report: {e}")

    # Add both the extracted report vulnerabilities and current risks to the context
    context = (
        f"Report Vulnerabilities:\n{json.dumps(extracted_vulnerabilities, indent=2)}\n\n"
        f"Current Risks:\n{json.dumps(current_risks, indent=2)}"
    )

    model = genai.GenerativeModel(model_name=MODEL_NAME)

    while retry_count < max_retries:
        print(f"--- Calling Gemini API with model: {MODEL_NAME} (Attempt {retry_count + 1}/{max_retries}) ---")
        
        try:
            response = model.generate_content(
                contents=[_create_risk_prompt(), context + "\n\n" + example],
                generation_config={
                    'response_mime_type': 'application/json',
                    'response_schema': {
                        "type": "object",
                        "properties": {
                            "new vulnerabilities": {
                                "type": "array",
                                "description": "A list of all new identified cybersecurity risks/vulnerabilities from the report.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "risk_name": {
                                            "type": "string",
                                            "description": "A concise, descriptive name for the risk (e.g., 'SQL Injection Vulnerability', 'Outdated Library')."
                                        },
                                        "overview": {
                                            "type": "string",
                                            "description": "A text summary of the risk, explaining what it is, its impact, and how it was identified."
                                        },
                                        "severity": {
                                            "type": "string",
                                            "description": "The calculated severity score (Critical, High, Medium, Low, or Info) for the risk."
                                        },
                                        "affected_elements": {
                                            "type": "array",
                                            "description": "A list of system components, files, URLs, or specific functions/code areas affected by this risk.",
                                            "items": {
                                                "type": "string"
                                            }
                                        },
                                        "recommendations": {
                                            "type": "object",
                                            "description": "Specific recommendations for mitigating the risk.",
                                            "properties": {
                                                "easy_fix": {
                                                    "type": "string",
                                                    "description": "A quick, immediate, or easy-to-implement mitigation step."
                                                },
                                                "long_term_fix": {
                                                    "type": "string",
                                                    "description": "A more difficult, time-consuming, or comprehensive architectural fix, if necessary."
                                                }
                                            }
                                        }
                                    },
                                    "required": [
                                        "risk_name",
                                        "overview",
                                        "severity",
                                        "affected_elements",
                                        "recommendations"
                                    ]
                                }
                            },
                            "all vulnerabilities": {
                                "type": "array",
                                "description": "A list of all cybersecurity risks/vulnerabilities.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "risk_name": {
                                            "type": "string",
                                            "description": "A concise, descriptive name for the risk (e.g., 'SQL Injection Vulnerability', 'Outdated Library')."
                                        },
                                        "overview": {
                                            "type": "string",
                                            "description": "A text summary of the risk, explaining what it is, its impact, and how it was identified."
                                        },
                                        "severity": {
                                            "type": "string",
                                            "description": "The calculated severity score (Critical, High, Medium, Low, or Info) for the risk."
                                        },
                                        "affected_elements": {
                                            "type": "array",
                                            "description": "A list of system components, files, URLs, or specific functions/code areas affected by this risk.",
                                            "items": {
                                                "type": "string"
                                            }
                                        },
                                        "recommendations": {
                                            "type": "object",
                                            "description": "Specific recommendations for mitigating the risk.",
                                            "properties": {
                                                "easy_fix": {
                                                    "type": "string",
                                                    "description": "A quick, immediate, or easy-to-implement mitigation step."
                                                },
                                                "long_term_fix": {
                                                    "type": "string",
                                                    "description": "A more difficult, time-consuming, or comprehensive architectural fix, if necessary."
                                                }
                                            }
                                        }
                                    },
                                    "required": [
                                        "risk_name",
                                        "overview",
                                        "severity",
                                        "affected_elements",
                                        "recommendations"
                                    ]
                                }
                            }
                        },
                        "required": ["new vulnerabilities", "all vulnerabilities"]
                    }
                }
            )

            if not response.text:
                print(f"[WARNING] Empty response text on attempt {retry_count + 1}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

            try: 
                json_data = json.loads(response.text)
                print(f"--- Finished creating response successfully on attempt {retry_count + 1}! ---")
                return response.text
            
            except json.JSONDecodeError as e:
                print(f"[ERROR in _add_risks] Response text is not valid JSON on attempt {retry_count + 1}. Error: {e}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

        except Exception as e:
            print(f"[ERROR in _add_risks] API call failed on attempt {retry_count + 1}: {e}. Retrying in {delay} seconds...")
            retry_count += 1
            time.sleep(delay)
            continue

    print(f"--- FAILED to generate risk content after {max_retries} attempts. ---")
    return None

def ai_generation_service(personal_info: dict, current_risks: dict, context_filepath: str, system_instruction: str = ""):
    """
    Generates a report and risks using Gemini, then saves to PostgreSQL.
    """

    report_json_str = _generate_report_content(context_filepath, system_instruction)

    if not report_json_str:
        print("[ERROR] Report generation failed.")
        return False

    try:
        report_data = json.loads(report_json_str)
        
        org = Organization.objects.get(organization_id=personal_info.get('organization_id'))
        user_id = personal_info.get('user_id') 
        user = User.objects.get(user_id=user_id) if user_id else None

        with transaction.atomic():
            new_report = Report.objects.create(
                user_created=user,
                organization=org,
                report_name=f"Security Assessment - {org.org_name} - {timezone.now().strftime('%Y-%m-%d')}",
                report_text=report_data, 
                completed=timezone.now()
            )

            risks_json_str = _add_risks(report_data, current_risks)
            
            if risks_json_str:
                risks_data = json.loads(risks_json_str)
                
                for risk_item in risks_data.get('new vulnerabilities', []):
                    Risk.objects.create(
                        risk_name=risk_item.get('risk_name'),
                        report=new_report, 
                        organization=org,
                        overview=risk_item.get('overview'),
                        recommendations=risk_item.get('recommendations'),
                        severity=risk_item.get('severity'),
                        affected_elements=", ".join(risk_item.get('affected_elements', [])),
                    )
            
            print(f"--- Successfully saved Report {new_report.report_id} and associated risks. ---")
            return True

    except Organization.DoesNotExist:
        print(f"[ERROR] Organization with ID {personal_info.get('organization_id')} not found.")
    except User.DoesNotExist:
        print(f"[ERROR] User with ID {personal_info.get('user_id')} not found.")
    except Exception as e:
        print(f"[ERROR] Database save failed: {e}")
        
    return False