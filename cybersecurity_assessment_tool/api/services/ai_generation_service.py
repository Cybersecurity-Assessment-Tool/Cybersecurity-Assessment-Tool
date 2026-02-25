from datetime import time
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
    sys.stderr.write("Error: GEMINI_API_KEY not found in environment variables. Please set it.")
    # Using placeholder will allow initalization, but calls will fail until user provides a real key.
    genai.configure(api_key="placeholder_key")

# Change the model here
MODEL_NAME = 'gemini-2.5-flash'

def _create_report_prompt():
    """
    Creates the report prompt to use for each report generation.

    Returns:
        str : A block string containing the report prompt. 
            Common leading whitespace are removed from every line.
    """
    return f"""You are an expert-level Cybersecurity Analyst and LaTeX Report Generator. 
    Your task is to receive a list of JSON objects containing raw technical data (dig outputs, port scans) and a questionnaire. 
    You must analyze, correlate, and synthesize this data into a single, complete, and professional LaTeX report.

    Core Instructions:
    1. Parse & Correlate: You must parse all JSON inputs. The data is fragmented, so you must correlate it:
        - The structured JSON (questionnaire) provides the "Organization Name," "Email Domain," and primary "External IP."
        - The dig output for the domain (e.g., valier.k12.mt.us) provides the A records (Website Hosting IPs), NS records (DNS Hoster), MX records (Email Provider), and TXT record (SPF).
        - The dig output for _dmarc provides the DMARC policy.
        - The port scan results must be matched to their respective IPs (the "External IP" from the questionnaire vs. the "Website Hosting IPs" from the A records).

    2. Analyze & Synthesize: Do not just list the data. You must analyze it.
        - Synthesize the questionnaire answers (e.g., all "Yes" answers) into a summary table and a brief analytical text.
        - Analyze the technical records. For example, identify that p=reject is a strong DMARC policy, that aspmx.l.google.com means Google Workspace is the email provider, and that "no ports open" on the firewall is a secure configuration.
        - Extract the date from the port scan logs (e.t., 2025-07-18) and use it as the report date.

    3. Generate New Content: The report must include analytical sections that are not directly in the JSON. You will generate these based on your analysis of the data and cybersecurity best practices:
        - An "Overview" section.
        - A "Risk Assessment & Readiness Summary" table.
        - A "Recommendations" section (e.g., verify DKIM, create an incident response plan).
        - A "Conclusion" section.
    """

def _create_risk_prompt():
    """
    Creates the risk prompt to use for each risk list generation.

    Returns:
        str : A triple-single-quote block string containing the risk prompt.
            Common leading whitespace are removed from every line.
    """
    return f"""You are an expert cybersecurity analyst tasked with converting a technical LaTeX vulnerability report into a structured JSON format. You are also given a list of current risks. Do not repeat risks that are already in this list. If it is empty, there are no current risks reported for this organization. It is your job to create new risks.
    Your goal is to extract all explicit and implicit risks and map them precisely to the provided JSON schema. Do not include any text outside of the JSON block in your final response.

    Focus Areas for Extraction:
        - Risk Name & Overview: Identify distinct vulnerabilities (e.g., exposed ports, missing policies, weak email configuration) and summarize them.
        - Affected Elements: Note the specific IP addresses, ports, domains, or controls mentioned (e.g., Port 3389 (RDP), email domain DMARC, MFA for Email).
        - Recommendations: Match the fixes mentioned in the report's Recommendations section to the easy_fix and long_term_fix fields.
        - CVSS Score: Assign an appropriate severity score (1-10) based on the report's assessment (e.g., Critical, High, Medium, Low) and the nature of the vulnerability. Critical/Severely exposed services should be high (e.g., 8-10).
        - Resources: Since the report does not provide links, use your knowledge to provide relevant, high-quality public links (YouTube or websites) for the proposed fixes, such as implementing DMARC or securing RDP/SSH.
    """

def _create_example(example_data: json, example_result: json):
    """
    Creates an example for the AI to reference as a template.
    
    Args:
        example_data: A JSON of the example context.
        example_result: A JSON of what the output should look like. 
    
    Returns:
        str | 'Example: ': A single string containing the example prompt, the example data, 
        and result converted into string format, otherwise a string with only 'Example:' in the front.
    """
    return 'Example:\n' + json.dumps(example_data) + '\n\n' + json.dumps(example_result)

def _generate_report_content(context: str, system_instruction: str = "", max_retries=4, delay=2):
    """
    Calls the AI model to generate report content based on a tested, hard-coded user prompt,
    context data given per call, hard-coded example, and optional system instruction.
    Retries on API error, or empty response, up to max_retries.

    Args:
        context: A filepath to the JSON file representing the context to be fed into the model (DNS DIG, port scans, etc.).
                See the context.json file in the report_template folder for how the JSON file should be structured.
        system_instruction: An optional instruction to the model to determine its tone of voice.

    Returns:
        JSON | None: The generated report as a JSON or None if there was an error.
    """
    
    retry_count = 0

    # creating example 
    test_report = ''
    with open("../assets/report_template/test_report.tex", 'r') as file:
        test_report += file.read()

    example = _create_example("../assets/report_template/context.json", test_report)

    while retry_count < max_retries:
        print(f"--- Calling Gemini API with model: {MODEL_NAME} (Attempt {retry_count + 1}/{max_retries}) ---")
        
        try:
            response = MODEL_NAME.generate_content(
                contents=[_create_report_prompt(), context + "\n" + example],
                system_instruction=system_instruction,
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
                                                        "Severity": {
                                                            "type": "string",
                                                            "description": "The calculated severity score (Critical, High, Medium, Low, or Info) for the risk."
                                                        },
                                                        "Overview": {
                                                            "type": "string",
                                                            "description": "A text description of the risk, explaining what it is, its impact, and how it was identified."
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
                                                "easy_fix": {
                                                    "type": "string",
                                                    "description": "A quick, immediate, or easy-to-implement mitigation step."
                                                },
                                                "long_term_fix": {
                                                    "type": "string",
                                                    "description": "A more difficult, time-consuming, or comprehensive architectural fix, if necessary."
                                                },
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
                        "required": ["report"]
                        }
                    }
                }
            )

            # check for empty response (retry on empty)
            if not response.text:
                print(f"[WARNING] Empty response text on attempt {retry_count + 1}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

            # check for valid JSON (retry on JSONDecodeError)
            try: 
                # attempt to parse as JSON
                json_data = json.loads(response.text)
                
                # if parsing succeeds, we have valid JSON
                
                print(f"--- Finished creating response successfully on attempt {retry_count + 1}! ---")
                return response.text
            
            except json.JSONDecodeError as e:
                # if JSON parsing fails, the response is not valid JSON
                print(f"[ERROR in generate_report_content] Response text is not valid JSON on attempt {retry_count + 1}. Error: {e}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

        # handle general API errors (retry on Exception)
        except Exception as e:
            print(f"[ERROR in generate_report_content] API call failed on attempt {retry_count + 1}: {e}. Retrying in {delay} seconds...")
            retry_count += 1
            time.sleep(delay)
            continue

    # if the loop finishes without returning, all retries have failed
    print(f"--- FAILED to generate report content after {max_retries} attempts. ---")
    return None

def _add_risks(report: json, current_risks: json, max_retries=4, delay=2):
    """
    Calls the AI model to add the new risks to the database based on the JSON formatted report given.
    Retries on API error, empty response, or invalid JSON, up to max_retries.

    Args:
        report: The newly generated JSON cybersecurity report.
        current_risks: The JSON of the current risks the organization is facing to check for duplicates.
    
    Returns:
        JSON | None: The generated report as a JSON or None if there was an error.
    """

    retry_count = 0
    
    # TODO: Fix this so that it takes a report and current risks template -> removes duplicates, returns JSON with distinct risks
    test_report = ''
    with open("../assets/risk_template/context.tex", 'r') as file:
        test_report += file.read()

    example = _create_example(test_report, "../assets/risk_template/test_risk_list.json")
    example += "\nOrganization's current risks: " + json.dumps(current_risks)

    while retry_count < max_retries:
        print(f"--- Calling Gemini API with model: {MODEL_NAME} (Attempt {retry_count + 1}/{max_retries}) ---")
        
        try:
            response = MODEL_NAME.generate_content(
                contents=[_create_risk_prompt(), json.dumps(report) + "\n" + example],
                generation_config={
                    'response_mime_type': 'application/json',
                    'response_schema': {
                        "type": "object",
                        "properties": {
                            "vulnerabilities": {
                                "type": "array",
                                "description": "A list of identified cybersecurity risks/vulnerabilities from the report.",
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
                                                },
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
                        "required": ["vulnerabilities"]
                        }
                    }
                }
            )

            # check for empty response (retry on empty)
            if not response.text:
                print(f"[WARNING] Empty response text on attempt {retry_count + 1}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

            # check for valid JSON (retry on JSONDecodeError)
            try: 
                # attempt to parse as JSON
                json_data = json.loads(response.text)
                
                # if parsing succeeds, we have valid JSON
                
                print(f"--- Finished creating response successfully on attempt {retry_count + 1}! ---")
                return response.text
            
            except json.JSONDecodeError as e:
                # if JSON parsing fails, the response is not valid JSON
                print(f"[ERROR in generate_report_content] Response text is not valid JSON on attempt {retry_count + 1}. Error: {e}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

        # handle general API errors (retry on Exception)
        except Exception as e:
            print(f"[ERROR in generate_report_content] API call failed on attempt {retry_count + 1}: {e}. Retrying in {delay} seconds...")
            retry_count += 1
            time.sleep(delay)
            continue

    # if the loop finishes without returning, all retries have failed
    print(f"--- FAILED to generate report content after {max_retries} attempts. ---")
    return None

def ai_generation_service(personal_info: json, current_risks: json, context: str, system_instruction: str = ""):
    """
    Generates a report and risks using Gemini, then saves to PostgreSQL.

    Args:
        personal_info: A JSON of the organization's personal information such os Org Name, IP address, questionnaire questions, etc.
        current_risks: A JSON of the organization's current risks.
        context: A filepath to the JSON file representing the context to be fed into the model (DNS DIG, port scans, etc.).
                See the context.json file in the report_template folder for how the JSON file should be structured.
        system_instruction: An optional instruction to the model to determine its tone of voice.

    Returns:
        True | False: Returns True if successfully, False otherwise.
    """

    report_json_str = _generate_report_content(context, system_instruction)

    if not report_json_str:
        print("[ERROR] Report generation failed.")
        return False

    try:
        # Generate the Report
        report_data = json.loads(report_json_str)
        
        # Get the Organization and User instances
        # personal_info should contain organization_id or similar unique identifier
        org = Organization.objects.get(organization_id=personal_info['organization_id'])
        user = User.objects.get(user_id=User.user_id)

        with transaction.atomic():
            # Create the Report record
            new_report = Report.objects.create(
                user_created=user,
                organization=org,
                report_name=f"Security Assessment - {org.org_name} - {timezone.now().strftime('%Y-%m-%d')}",
                report_text=report_data, # Saves the full JSON structure
                completed=timezone.now()
            )

            # Generate the Risks based on the new report
            risks_json_str = _add_risks(report_data, current_risks)
            
            if risks_json_str:
                risks_data = json.loads(risks_json_str)
                
                # Iterate through risks and save to database
                for risk_item in risks_data.get('vulnerabilities', []):
                    Risk.objects.create(
                        risk_name=risk_item.get('risk_name'),
                        report=new_report, # Links the risk to the report ID
                        organization=org,
                        overview=risk_item.get('overview'),
                        recommendations=risk_item.get('recommendations'),
                        severity=risk_item.get('severity'),
                        # affected_elements is a TextField in model, but AI returns a list
                        affected_elements=", ".join(risk_item.get('affected_elements', [])),
                    )
            
            print(f"--- Successfully saved Report {new_report.report_id} and associated risks. ---")
            return True

    except Organization.DoesNotExist:
        print(f"[ERROR] Organization with ID {personal_info.get('organization_id')} not found.")
    except User.DoesNotExist:
        print(f"[ERROR] User with ID {User.user_id} not found.")
    except Exception as e:
        print(f"[ERROR] Database save failed: {e}")
        
    return False