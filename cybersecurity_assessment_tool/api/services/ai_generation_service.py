from datetime import time
import json
import os
import sys
from typing import List
from dotenv import load_dotenv, find_dotenv
import google.generativeai as genai

load_dotenv(find_dotenv())

try: 
    API_KEY = os.environ["GEMINI_API_KEY"]
    genai.configure(api_key=API_KEY)
except KeyError:
    sys.stderr.write("Error: GEMINI_API_KEY not found in environment variables. Please set it.")
    # Using placeholder will allow initalization, but calls will fail until user provides a real key.
    genai.configure(api_key="placeholder_key")

def _json_to_str(filepaths: List[str]):
    """
    Creates a single compiled string of the JSON files provided.

    Args:
        filepaths: The filepaths to the JSON files.
    
    Returns:
        str | '': A single string containing the JSON file's name and the 
        JSON file's content separated by new lines, otherwise an empty string.
    """
    result = ''
    for file in filepaths:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                result += f"{file}:\n{json.dumps(data,indent=2)}\n--\n"
        
        except FileNotFoundError:
            f"[ERROR in _json_to_str] File not found at path: {file}"
        except json.JSONDecodeError:
            f"[ERROR in _json_to_str] Failed to decode JSON from file: {file}. Please check the file's syntax."
        except Exception as e:
            f"[ERROR in _json_to_str] An unexpected error occured: {e}"

    return result

def _create_example(example_prompt: str, example_data: str, example_result: str):
    """
    Creates an example for the AI to reference as a template.
    
    Args:
        example_prompt: The question or task that was asked to generate this result.
        example_data: A compiled string of JSON files with the example context.
        example_result: A string of what the output should look like. Can be any output type but MUST be converted to a string.
    
    Returns:
        str | 'Example: ': A single string containing the example prompt, the example data, 
        and result converted into string format, otherwise a string with only 'Example:' in the front.
    """
    return 'Example:\n' + example_prompt + '\n' + example_data + example_result

def generate_report_content(prompt: str, context: str, example: str, system_instruction: str = "", max_retries=4, delay=2):
    """
    Calls the AI model to generate report content based on a user prompt,
    context, example, and optional system instruction.
    Retries on API error, empty response, or invalid JSON, up to max_retries.
    The model currently being used is Gemini 2.5 Flash.

    Args:
        prompt: A question or task you want answered or generated from the AI.
        context: A compiled string of JSON files representing the context to be fed into the model.
        example: A compiled list of a different context with a result you want the AI to reference as a template.
        system_instruction: An optional instruction to the model to determine its tone of voice.

    Returns:
        JSON formatted string | None: The generated report as a JSON or None if there was an error.
    """

    model_name = 'gemini-2.5-flash'
    
    retry_count = 0

    while retry_count < max_retries:
        print(f"--- Calling Gemini API with model: {model_name} (Attempt {retry_count + 1}/{max_retries}) ---")
        
        try:
            response = model_name.generate_content(
                contents=[prompt, context + "\n" + example],
                system_instruction=system_instruction,
                generation_config={
                    'response_mime_type': 'application/json',
                    'response_schema': {
                        'type':'object',
                        'properties': {
                            'Overview': {'type': 'string'},
                            'Organizational Information': {'type': 'array', 'items': {'type': 'string'}},
                            'Security Questionnaire Review': {'type': 'array', 'items': {'type': 'string'}},
                            'DNS & Email Security': {'type': 'array', 'items': {'type': 'string'}},
                            'Port Scanning Results': {'type': 'array', 'items': {'type': 'string'}},
                            'Risk Assessment & Readiness Summary': {'type': 'array', 'items': {'type': 'string'}},
                            'Recommendations': {'type': 'array', 'items': {'type': 'string'}},
                            'Conclusion': {'type': 'string'},
                        },
                        'required': ['Overview', 'Organizational Information', 'Security Questionnaire Review', 'DNS & Email Security', 'Port Scanning Results', 'Risk Assessment & Readiness Summary', 'Recommendations', 'Conclusion']
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
    
def generate_risks(report):
    """
    Calls the AI model to generate risks based on the report given.
    The model currently being used is Gemini 2.5 Flash.

    Args:
        report: A JSON containing the cybersecurity report generated.
    
    Returns:
        A list of risks- which are JSON objects with a name, overview,
        recommendation, severity, and affected values.
    """

    # Haven't written yet, still need to generate template risks
    return report