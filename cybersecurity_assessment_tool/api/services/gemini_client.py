# api/services/gemini_client.py

import json
from typing import Dict, Any
from django.conf import settings
from google import genai
from google.genai import types
import jsonschema

RESPONSE_SCHEMA_TYPED = types.Schema(
    type=types.Type.OBJECT,
    properties={
        "summary": types.Schema(type=types.Type.STRING),
        "key_points": types.Schema(
            type=types.Type.ARRAY,
            items=types.Schema(type=types.Type.STRING),
        ),
        "sentiment": types.Schema(
            type=types.Type.STRING,
            enum=["positive", "neutral", "negative"],
        ),
    },
    required=["summary", "key_points", "sentiment"],
)

# Optional: keep jsonschema validation (use a plain JSON schema for local validation)
RESPONSE_SCHEMA_JSON: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "key_points": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        "sentiment": {"type": "string", "enum": ["positive", "neutral", "negative"]},
    },
    "required": ["summary", "key_points", "sentiment"],
}

def call_gemini_json(prompt: str) -> Dict[str, Any]:
    client = genai.Client(api_key=settings.GEMINI_API_KEY)

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=RESPONSE_SCHEMA_TYPED,
        ),
    )

    if not response.text:
        raise RuntimeError("Empty response from Gemini.")

    data = json.loads(response.text)
    jsonschema.validate(instance=data, schema=RESPONSE_SCHEMA_JSON)
    return data
