import json
import os
import sys
import google.generativeai as gen
from django.utils import timezone
import jsonschema
from google.genai import types
from typing import Dict, Any
from django.conf import settings
from google.api_core.exceptions import ResourceExhausted, ServiceUnavailable, DeadlineExceeded

# -----------------------------------------------------------------------------
# MODEL SETUP
# -----------------------------------------------------------------------------

gen.configure(api_key=settings.API_KEY)

# Change the model here
MODEL_NAME = 'gemini-2.5-pro'
model = gen.GenerativeModel(model_name=MODEL_NAME)

# -----------------------------------------------------------------------------
# REPORT SCHEMA
# -----------------------------------------------------------------------------

REPORT_SCHEMA_JSON: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "thought": {
            "type": "string",
            "description": "Your internal reasoning process and analysis before generating the report."
        },
        "report": {
            "type": "array",
            "description": "A cybersecurity assessment report on an organization's current security risks.",
            "items": {
                "type": "object",
                "properties": {
                    "Risks & Recommendations": {
                        "type": "object",
                        "description": "A paragraph summary of the organization's network and a list of found vulnerabilites.",
                        "properties": { 
                            "Summary": {
                                "type": "string",
                                "description": "A summary of the organization's network."
                            },
                            "Vulnerabilities Found": {
                                "type": "array",
                                "description": "A list of found vulnerabilities.",
                                "items": { 
                                    "type": "object",
                                    "properties": {
                                        "Risk": {"type": "string", "description": "A short name of what the risk is."},
                                        "Overview": {"type": "string", "description": "A concise text description (maximum 3 sentences) of the observation, explaining what it is, its impact, and how it was identified."},
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
                                    },
                                    "required": ["Risk", "Overview", "Severity", "Affected Elements", "Recommendation"]
                                }
                            }
                        },
                        "required": ["Summary", "Vulnerabilities Found"]
                    },
                    "Observations": {
                        "type": "array",
                        "description": "A list of what the organization did well.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "Observation": {"type": "string", "description": "A short name of what the observation is."},
                                "Overview": {"type": "string", "description": "A text description of the observation, explaining what it is, its impact, and how it was identified."},
                                "Affected Elements": {
                                    "type": "array",
                                    "description": "A list of system components, files, URLs, or specific functions/code areas involved by this observation.",
                                    "items": {"type": "string"}
                                }
                            },
                            "required": ["Observation", "Overview", "Affected Elements"]
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
    "required": ["thought", "report"]
}

# -----------------------------------------------------------------------------
# RISKS SCHEMA
# -----------------------------------------------------------------------------

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
            },
            "required": ["easy_fix", "long_term_fix"]
        }
    },
    "required": ["risk_name", "overview", "severity", "affected_elements", "recommendations"]
}

RISK_SCHEMA_JSON: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "thought": {
            "type": "string",
            "description": "Your internal reasoning process before extracting vulnerabilities."
        },
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
    "required": ["thought", "new vulnerabilities", "all vulnerabilities"]
}

def _create_report_prompt() -> str:
    """
    Creates the report prompt to use for each report generation.
    """
    return f"""You need to always respond in a JSON format. Only output valid JSON. 
    You are an expert cybersecurity analyst who generates comprehensive security reports. 
    You are evaluating raw technical data and a questionnaire for an organization. 
    If you do not have enough data to draw a conclusion, simply state you do not know.
    
    Every response you generate MUST include a "thought" key at the root level where you think through your analysis, followed by the "report" key.
    
    Pass the formatted vulnerabilities and summaries into the "report" section EXACTLY as formatted in the schema.
    Draw conclusions (e.g., p=reject is strong, no open ports are secure) rather than just listing data. 
    Do not include conversational text or markdown. Do not include the example in your response. 
    
    EXPECTED SCHEMA STRUCTURE:
    {json.dumps(REPORT_SCHEMA_JSON, indent=2)}
    """

def _create_risk_prompt() -> str:
    """
    Creates the risk prompt to use for each risk list generation.
    """
    return f"""You need to always respond in a JSON format. Only output valid JSON. 
    You are an expert cybersecurity analyst who extracts vulnerabilities. 
    You are evaluating a security report for an organization. 
    If you do not have enough data to assess a risk, simply state you do not know. 
    You need to make sure you cross-reference every vulnerability against the list of existing risks during your analysis.
    
    Every response you generate MUST include a "thought" key at the root level where you think through your analysis, followed by the vulnerability lists.
    
    The current risk list tells you which risks are already known. 
    Each entry corresponds to a vulnerability already tracked by the organization. 
    Pass all new vulnerabilities that are NOT in the known risk list into the "new vulnerabilities" section.
    Assign accurate severities and provide an 'easy_fix' and 'long_term_fix'.
    Do not include any conversational text or markdown. Do not include the example in your response.
    Do not include any issues with the network scan in your response.
    
    EXPECTED SCHEMA STRUCTURE:
    {json.dumps(RISK_SCHEMA_JSON, indent=2)}
    """

def _create_example(example_input, example_output) -> str:
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

def _generate_report_content(questionnaire, context, chunk_callback=None):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(current_dir, "..", "assets", "report_template", "input.json")
    output_path = os.path.join(current_dir, "..", "assets", "report_template", "output.json")

    example = _create_example(os.path.normpath(input_path), os.path.normpath(output_path))

    print(f"--- Calling Gemini API with model: {MODEL_NAME} ---")
    full_prompt = f"{_create_report_prompt()}\n\nContext Input:\n{context}\n{questionnaire}\n\nExample:\n{example}"

    response = model.generate_content(
        contents=full_prompt,
        generation_config=gen.types.GenerationConfig(
            response_mime_type="application/json",
            response_schema=REPORT_SCHEMA_JSON
        ),
        stream=True  # 1. Enable streaming
    )

    full_text = ""
    
    # 2. Iterate through the chunks as Google sends them
    for chunk in response:
        if chunk.text:
            full_text += chunk.text
            print("Chunk: " + chunk.text + "\n")
            # 3. Fire the callback to push the chunk up to the Django worker
            if chunk_callback:
                chunk_callback(chunk.text)

    if not full_text:
        raise RuntimeError("Empty response from Gemini for report generation.")

    # 4. Once the stream finishes, parse the accumulated text into JSON
    data = json.loads(full_text)
    jsonschema.validate(instance=data, schema=REPORT_SCHEMA_JSON)
            
    return data

def _add_risks(report: dict, current_risks: dict):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    current_risk_path = os.path.join(current_dir, "..", "assets", "risk_template", "current_risk.json")
    output_path = os.path.join(current_dir, "..", "assets", "risk_template", "output.json")
    input_path = os.path.join(current_dir, "..", "assets", "risk_template", "input.json")
    
    with open(os.path.normpath(current_risk_path), 'r', encoding='utf-8') as f:
        example_current_risk = json.load(f)
    
    example = _create_example(os.path.normpath(input_path), os.path.normpath(output_path))
    
    extracted_vulnerabilities = []
    if "report" in report and isinstance(report["report"], list) and len(report["report"]) > 0:
        readiness_section = report["report"][0].setdefault("Risks & Recommendations", {})
        extracted_vulnerabilities = readiness_section.get("Vulnerabilities Found", [])

    context = (
        f"Report Vulnerabilities:\n{json.dumps(extracted_vulnerabilities, indent=2)}\n\n"
        f"Current Risks:\n{json.dumps(current_risks, indent=2)}"
    )

    print(f"--- Calling Gemini API with model: {MODEL_NAME} ---")
    full_prompt = f"{_create_risk_prompt()}\n\nContext Input:\n{context}\n\nExample:\n{example}\n\nExample Current Risks:\n{example_current_risk}"
        
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
        
    return data

def ai_generation_service(questionnaire: dict, current_risks: dict, context: str, chunk_callback=None):
    """
    Generates report and risks data using Gemini.
    Accepts an optional chunk_callback(text) to stream report progress.
    Returns: (report_data, risks_data, error_message)
    """
    try:
        # Pass the callback down to the report generator
        report_data = _generate_report_content(questionnaire, context, chunk_callback)
        risks_data = _add_risks(report_data, current_risks)
        print("--- Successfully generated report and risk data dictionaries. ---")
        return report_data, risks_data, None

    except ResourceExhausted:
        msg = "The AI is currently experiencing high traffic. Please wait a moment and try again."
        print(f"[ERROR] {msg}")
        return None, None, msg
        
    except (ServiceUnavailable, DeadlineExceeded):
        msg = "The AI service timed out or is temporarily offline. Please try again later."
        print(f"[ERROR] {msg}")
        return None, None, msg
        
    except jsonschema.ValidationError as e:
        msg = "The AI generated an improperly formatted report. Please run the scan again."
        print(f"[ERROR] Schema validation failed: {e.message}")
        return None, None, msg
        
    except Exception as e:
        error_str = str(e).lower()
        if "safety" in error_str or "blocked" in error_str:
            msg = "The AI blocked the generation because the scan data triggered a safety filter."
        else:
            msg = "An unexpected error occurred while analyzing the scan data."
            
        print(f"[ERROR] AI Pipeline failed: {e}")
        return None, None, msg