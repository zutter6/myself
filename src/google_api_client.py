"""
Google API Client - Handles all communication with Google's Gemini API.
This module is used by both OpenAI compatibility layer and native Gemini endpoints.
"""
import json
import requests
from fastapi import Response
from fastapi.responses import StreamingResponse
from google.auth.transport.requests import Request as GoogleAuthRequest

from .auth import get_credentials, save_credentials, get_user_project_id, onboard_user
from .utils import get_user_agent
from .config import CODE_ASSIST_ENDPOINT, DEFAULT_SAFETY_SETTINGS


def send_gemini_request(payload: dict, is_streaming: bool = False) -> Response:
    """
    Send a request to Google's Gemini API.
    
    Args:
        payload: The request payload in Gemini format
        is_streaming: Whether this is a streaming request
        
    Returns:
        FastAPI Response object
    """
    # Get and validate credentials
    creds = get_credentials()
    if not creds:
        return Response(
            content="Authentication failed. Please restart the proxy to log in.", 
            status_code=500
        )
    

    # Refresh credentials if needed
    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(GoogleAuthRequest())
            save_credentials(creds)
        except Exception as e:
            return Response(
                content="Token refresh failed. Please restart the proxy to re-authenticate.", 
                status_code=500
            )
    elif not creds.token:
        return Response(
            content="No access token. Please restart the proxy to re-authenticate.", 
            status_code=500
        )

    # Get project ID and onboard user
    proj_id = get_user_project_id(creds)
    if not proj_id:
        return Response(content="Failed to get user project ID.", status_code=500)
    
    onboard_user(creds, proj_id)

    # Build the final payload with project info
    final_payload = {
        "model": payload.get("model"),
        "project": proj_id,
        "request": payload.get("request", {})
    }

    # Determine the action and URL
    action = "streamGenerateContent" if is_streaming else "generateContent"
    target_url = f"{CODE_ASSIST_ENDPOINT}/v1internal:{action}"
    if is_streaming:
        target_url += "?alt=sse"

    # Build request headers
    request_headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }

    final_post_data = json.dumps(final_payload)

    # Send the request
    if is_streaming:
        resp = requests.post(target_url, data=final_post_data, headers=request_headers, stream=True)
        return _handle_streaming_response(resp)
    else:
        resp = requests.post(target_url, data=final_post_data, headers=request_headers)
        return _handle_non_streaming_response(resp)


def _handle_streaming_response(resp) -> StreamingResponse:
    """Handle streaming response from Google API."""
    import asyncio
    
    async def stream_generator():
        try:
            with resp:
                resp.raise_for_status()
                
                
                for chunk in resp.iter_lines():
                    if chunk:
                        if not isinstance(chunk, str):
                            chunk = chunk.decode('utf-8')
                            
                                                    
                        if chunk.startswith('data: '):
                            chunk = chunk[len('data: '):]
                            
                            try:
                                obj = json.loads(chunk)
                                
                                if "response" in obj:
                                    response_chunk = obj["response"]
                                    response_json = json.dumps(response_chunk, separators=(',', ':'))
                                    response_line = f"data: {response_json}\n\n"
                                    yield response_line
                                    await asyncio.sleep(0)
                            except json.JSONDecodeError:
                                continue
                
        except requests.exceptions.RequestException as e:
            yield f'data: {{"error": {{"message": "Upstream request failed: {str(e)}"}}}}\n\n'.encode('utf-8')
        except Exception as e:
            yield f'data: {{"error": {{"message": "An unexpected error occurred: {str(e)}"}}}}\n\n'.encode('utf-8')

    response_headers = {
        "Content-Type": "text/event-stream",
        "Content-Disposition": "attachment",
        "Vary": "Origin, X-Origin, Referer",
        "X-XSS-Protection": "0",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Server": "ESF"
    }
    
    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers=response_headers
    )


def _handle_non_streaming_response(resp) -> Response:
    """Handle non-streaming response from Google API."""
    if resp.status_code == 200:
        try:
            google_api_response = resp.text
            if google_api_response.startswith('data: '):
                google_api_response = google_api_response[len('data: '):]
            google_api_response = json.loads(google_api_response)
            standard_gemini_response = google_api_response.get("response")
            return Response(
                content=json.dumps(standard_gemini_response), 
                status_code=200, 
                media_type="application/json; charset=utf-8"
            )
        except (json.JSONDecodeError, AttributeError) as e:
            return Response(
                content=resp.content, 
                status_code=resp.status_code, 
                media_type=resp.headers.get("Content-Type")
            )
    else:
        return Response(
            content=resp.content, 
            status_code=resp.status_code, 
            media_type=resp.headers.get("Content-Type")
        )


def build_gemini_payload_from_openai(openai_payload: dict) -> dict:
    """
    Build a Gemini API payload from an OpenAI-transformed request.
    This is used when OpenAI requests are converted to Gemini format.
    """
    # Extract model from the payload
    model = openai_payload.get("model")
    
    # Get safety settings or use defaults
    safety_settings = openai_payload.get("safetySettings", DEFAULT_SAFETY_SETTINGS)
    
    # Build the request portion
    request_data = {
        "contents": openai_payload.get("contents"),
        "systemInstruction": openai_payload.get("systemInstruction"),
        "cachedContent": openai_payload.get("cachedContent"),
        "tools": openai_payload.get("tools"),
        "toolConfig": openai_payload.get("toolConfig"),
        "safetySettings": safety_settings,
        "generationConfig": openai_payload.get("generationConfig", {}),
    }
    
    # Remove any keys with None values
    request_data = {k: v for k, v in request_data.items() if v is not None}
    
    return {
        "model": model,
        "request": request_data
    }


def build_gemini_payload_from_native(native_request: dict, model_from_path: str) -> dict:
    """
    Build a Gemini API payload from a native Gemini request.
    This is used for direct Gemini API calls.
    """
    # Add default safety settings if not provided
    if "safetySettings" not in native_request:
        native_request["safetySettings"] = DEFAULT_SAFETY_SETTINGS
    
    return {
        "model": model_from_path,
        "request": native_request
    }