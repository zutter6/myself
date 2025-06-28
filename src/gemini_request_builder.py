import json
import re

from .auth import get_user_project_id
from .utils import get_user_agent

CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com"

def build_gemini_request(post_data: bytes, full_path: str, creds, is_streaming: bool = False):
    try:
        incoming_json = json.loads(post_data)
    except (json.JSONDecodeError, AttributeError):
        incoming_json = {}

    # Set the action based on streaming
    action = "streamGenerateContent" if is_streaming else "generateContent"

    # The target URL is always one of two values
    target_url = f"{CODE_ASSIST_ENDPOINT}/v1internal:{action}"
    
    if is_streaming:
        target_url += "?alt=sse"

    # Extract model from the incoming JSON payload
    final_model = incoming_json.get("model")

    # Default safety settings if not provided
    safety_settings = incoming_json.get("safetySettings")
    if not safety_settings:
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"}
        ]

    # Build the final payload for the Google API
    structured_payload = {
        "model": final_model,
        "project": get_user_project_id(creds),
        "request": {
            "contents": incoming_json.get("contents"),
            "systemInstruction": incoming_json.get("systemInstruction"),
            "cachedContent": incoming_json.get("cachedContent"),
            "tools": incoming_json.get("tools"),
            "toolConfig": incoming_json.get("toolConfig"),
            "safetySettings": safety_settings,
            "generationConfig": incoming_json.get("generationConfig", {}),
        },
    }
    # Remove any keys with None values from the request
    structured_payload["request"] = {
        k: v
        for k, v in structured_payload["request"].items()
        if v is not None
    }
    
    final_post_data = json.dumps(structured_payload)

    # Build the request headers
    request_headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }

    return target_url, final_post_data, request_headers, is_streaming