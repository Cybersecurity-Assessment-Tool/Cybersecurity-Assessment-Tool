from datetime import time
import json
import os
import sys
import textwrap
from typing import Any, Dict, List, Union
from dotenv import load_dotenv, find_dotenv
import google.generativeai as genai
import re

load_dotenv(find_dotenv())

try: 
    API_KEY = os.environ["GEMINI_API_KEY"]
    genai.configure(api_key=API_KEY)
except KeyError:
    sys.stderr.write("Error: GEMINI_API_KEY not found in environment variables. Please set it.")
    # Using placeholder will allow initalization, but calls will fail until user provides a real key.
    genai.configure(api_key="placeholder_key")

MODEL_NAME = 'gemini-2.5-flash'

# defining the acceptable types for the JSON values for clarity
JSONVALUE = Union[str, int, float, bool, None, List[Any], Dict[str, Any]]

# TODO: Edit this to make it more comprehensive of the possible ways the AI could generate an incorrect LaTeX
def _check_latex_format(text):
    # check for common LaTeX commands (e.g., \section, \begin, \documentclass)
    if re.search(r'\\(section|subsection|chapter|begin|end|documentclass)', text):
        return True
    # check for math mode delimiters
    if re.search(r'\$.*?\$', text) or re.search(r'\\\[.*?\\\]', text, re.DOTALL):
        return True
    return False

def _format_json_to_custom_str(data: Union[Dict[str, JSONVALUE], List[JSONVALUE]], indent_level: int = 0) -> str:
    """
    Recursively formats a JSON object/array into the custom string representation.

    Args:
        data: The JSON data (dict or list) to format.
        indent_level: The current level of indentation (used for nested items).

    Returns:
        A string following the custom format rules.
    """
    indent_space = '  ' * indent_level  # two spaces per level

    if isinstance(data, dict):
        # handle dictionary members (key : value)
        lines = []
        for key, value in data.items():
            key_str = str(key)
            
            if isinstance(value, (dict, list)):
                # nested structure: key: { ... nested content ... }
                nested_content = _format_json_to_custom_str(value, indent_level + 1)
                
                # add newline for readability inside the braces for objects/arrays
                if isinstance(value, dict):
                    lines.append(f"{indent_space}{key_str}: {{\n{nested_content}{indent_space}}}")
                else: # list/array
                    lines.append(f"{indent_space}{key_str}: [\n{nested_content}{indent_space}]")
            else:
                # simple value: key: property
                value_str = json.dumps(value)
                lines.append(f"{indent_space}{key_str}: {value_str}")
        
        return '\n'.join(lines)

    elif isinstance(data, list):
        # handle array items
        lines = []
        for item in data:
            if isinstance(item, (dict, list)):
                # nested structure inside an array: { ... } or [ ... ]
                nested_content = _format_json_to_custom_str(item, indent_level + 1)
                
                if isinstance(item, dict):
                    lines.append(f"{indent_space}{{\n{nested_content}{indent_space}}}")
                else: # list/array within an array
                    lines.append(f"{indent_space}[\n{nested_content}{indent_space}]")
            else:
                # Simple value in array
                value_str = json.dumps(item)
                lines.append(f"{indent_space}{value_str}")
        
        return '\n'.join(lines)
    
    # should only be called with dict or list, but included for robustness
    return json.dumps(data)

def json_to_custom_str(filepath: str) -> str:
    """
    Converts a single JSON file into a custom string representation.

    The format removes outer curly braces, separates members with newlines, 
    and adds curly braces/brackets only around nested objects/arrays.

    Args:
        filepath: A filepath to the JSON file.
    
    Returns:
        str: A single string containing the JSON content formatted as required,
             or an error message string if the file cannot be processed.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # the main logic handles the core JSON structure (dict or list)
        if isinstance(data, (dict, list)):
            return _format_json_to_custom_str(data)
        else:
            # handle the case where the JSON root is a simple value (e.g., "hello" or 123)
            return json.dumps(data)
            
    except FileNotFoundError:
        return f"[ERROR in json_to_custom_str] File not found at path: {filepath}"
    except json.JSONDecodeError:
        return f"[ERROR in json_to_custom_str] Failed to decode JSON from file: {filepath}. Please check the file's syntax."
    except Exception as e:
        return f"[ERROR in json_to_custom_str] An unexpected error occurred: {e}"

def _create_report_prompt():
    """
    Creates the report prompt to use for each report generation.

    Returns:
        str : A block string containing the report prompt. 
            Common leading whitespace are removed from every line.
    """
    return textwrap.dedent(r'''You are an expert-level Cybersecurity Analyst and LaTeX Report Generator. 
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

    4. Strict LaTeX Formatting:
        - The output MUST be a single, complete LaTeX document.
        - It must start with \documentclass[12pt]{article} and end with \end{document}.
        - It MUST include the following packages in the preamble: geometry, pifont, booktabs, hyperref, url, and seqsplit.
        - Use booktabs (\toprule, \midrule, \bottomrule) for all tables.
        - Use \ding{51} Yes for "Yes" answers in the questionnaire table.
        - Use \seqsplit{\texttt{...}} for long technical strings (IP lists, DMARC/SPF records, MX records) to ensure they wrap correctly.
        - Use \url{...} for all domains and email addresses.
    ''')

def _create_risk_prompt():
    """
    Creates the risk prompt to use for each risk list generation.

    Returns:
        str : A triple-single-quote block string containing the risk prompt.
            Common leading whitespace are removed from every line.
    """
    return textwrap.dedent(r'''You are an expert cybersecurity analyst tasked with converting a technical LaTeX vulnerability report into a structured JSON format. You are also given a list of current risks. Do not repeat risks that are already in this list. If it is empty, there are no current risks reported for this organization. It is your job to create new risks.
    Your goal is to extract all explicit and implicit risks and map them precisely to the provided JSON schema. Do not include any text outside of the JSON block in your final response.

    Focus Areas for Extraction:
        - Risk Name & Overview: Identify distinct vulnerabilities (e.g., exposed ports, missing policies, weak email configuration) and summarize them.
        - Affected Elements: Note the specific IP addresses, ports, domains, or controls mentioned (e.g., Port 3389 (RDP), email domain DMARC, MFA for Email).
        - Recommendations: Match the fixes mentioned in the report's Recommendations section to the easy_fix and long_term_fix fields.
        - CVSS Score: Assign an appropriate severity score (1-10) based on the report's assessment (e.g., Critical, High, Medium, Low) and the nature of the vulnerability. Critical/Severely exposed services should be high (e.g., 8-10).
        - Resources: Since the report does not provide links, use your knowledge to provide relevant, high-quality public links (YouTube or websites) for the proposed fixes, such as implementing DMARC or securing RDP/SSH.
    ''')

def _create_example(example_data: str, example_result: str):
    """
    Creates an example for the AI to reference as a template.
    
    Args:
        example_data: A compiled string of the example context.
        example_result: A string of what the output should look like. 
                        Can be any output type but MUST be converted to a string.
    
    Returns:
        str | 'Example: ': A single string containing the example prompt, the example data, 
        and result converted into string format, otherwise a string with only 'Example:' in the front.
    """
    return 'Example:\n' + example_data + example_result

def generate_report_content(context: str, system_instruction: str = "", max_retries=4, delay=2):
    """
    Calls the AI model to generate report content based on a tested, hard-coded user prompt,
    context data given per call, hard-coded example, and optional system instruction.
    Retries on API error, empty response, or invalid LaTeX formatting, up to max_retries.
    The model currently being used is Gemini 2.5 Flash.

    Args:
        context: A filepath to the JSON file representing the context to be fed into the model (DNS DIG, port scans, etc.).
                See the context.json file in the report_template folder for how the JSON file should be structured.
        system_instruction: An optional instruction to the model to determine its tone of voice.

    Returns:
        LaTeX formatted string | None: The generated report as a LaTeX formatted string or None if there was an error.
    """
    
    retry_count = 0

    # creating example 
    test_report = ''
    with open("../assets/report_template/test_report.tex", 'r') as file:
        test_report += file.read()

    example = _create_example(json_to_custom_str("../assets/report_template/context.json"), test_report)

    while retry_count < max_retries:
        print(f"--- Calling Gemini API with model: {MODEL_NAME} (Attempt {retry_count + 1}/{max_retries}) ---")
        
        try:
            response = MODEL_NAME.generate_content(
                contents=[_create_report_prompt(), context + "\n" + example],
                system_instruction=system_instruction
            )

            # check for empty response (retry on empty)
            if not response.text:
                print(f"[WARNING in generate_report_content] Empty response text on attempt {retry_count + 1}. Retrying in {delay} seconds...")
                retry_count += 1
                time.sleep(delay)
                continue

            # check for valid LaTeX (retry on invalid)
            if _check_latex_format(response.text):
                print(f"--- Finished creating response successfully on attempt {retry_count + 1}! ---")
                return response.text
            else:
                print(f"[WARNING in generate_report_content] Not a valid LaTeX {retry_count + 1}: {e}. Retrying in {delay} seconds...")
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
    
def generate_risks(report: str, max_retries=4, delay=2):
    """
    Calls the AI model to generate risks based on the LaTeX formatted report given.
    Retries on API error, empty response, or invalid JSON, up to max_retries.
    The model currently being used is Gemini 2.5 Flash.

    Args:
        report: A JSON containing the cybersecurity report generated.
    
    Returns:
        A JSON list of risks- which are JSON objects with a name, overview,
        severity, affected elements, and recommendations 
        (easy fix, long term fix, and resources (type, url, description)).
    """

    retry_count = 0
    
    # creating example 
    test_report = ''
    with open("../assets/risk_template/context.tex", 'r') as file:
        test_report += file.read()

    example = _create_example(test_report, json_to_custom_str("../assets/risk_template/test_risk_list.json"))

    while retry_count < max_retries:
        print(f"--- Calling Gemini API with model: {MODEL_NAME} (Attempt {retry_count + 1}/{max_retries}) ---")
        
        try:
            response = MODEL_NAME.generate_content(
                contents=[_create_risk_prompt(), report + "\n" + example],
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
                                            "description": "A text summary of the risk, its impact, and how it was identified."
                                        },
                                        "severity_cvss_score": {
                                            "type": "number",
                                            "description": "The calculated severity score (1-10) for the risk, based on CVSS metrics. This should be an integer or a decimal number."
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
                                                "resources": {
                                                    "type": "array",
                                                    "description": "Links to external resources (YouTube videos, official documentation, articles) for assistance.",
                                                    "items": {
                                                        "type": "object",
                                                        "properties": {
                                                            "type": {
                                                                "type": "string",
                                                                "enum": ["youtube", "website", "documentation"],
                                                                "description": "The type of resource."
                                                            },
                                                            "url": {
                                                                "type": "string",
                                                                "format": "uri",
                                                                "description": "The URL of the resource."
                                                            },
                                                            "description": {
                                                                "type": "string",
                                                                "description": "A brief description of what the resource contains."
                                                            }
                                                        },
                                                        "required": ["type", "url"]
                                                    }
                                                }
                                            },
                                            "required": ["easy_fix", "resources"]
                                        }
                                    },
                                    "required": [
                                        "risk_name",
                                        "overview",
                                        "severity_cvss_score",
                                        "affected_elements",
                                        "recommendations"
                                    ]
                                }
                            }
                        },
                        "required": ["vulnerabilities"]
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
