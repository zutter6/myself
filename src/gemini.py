import json
import requests
from fastapi import APIRouter, Request, Response, Depends

from .auth import authenticate_user, get_credentials, get_user_project_id, onboard_user, save_credentials
from .utils import get_user_agent
from .gemini_request_builder import build_gemini_request
from .gemini_response_handler import handle_gemini_response

CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com"

router = APIRouter()

@router.get("/v1beta/models")
async def list_models(request: Request, username: str = Depends(authenticate_user)):
    """List available models - matching gemini-cli supported models exactly."""
    print(f"[GET] {request.url.path} - User: {username}")
    print(f"[MODELS] Serving models list (both /v1/models and /v1beta/models return the same data)")
    
    models_response = {
        "models": [
            {
                "name": "models/gemini-1.5-pro",
                "version": "001",
                "displayName": "Gemini 1.5 Pro",
                "description": "Mid-size multimodal model that supports up to 2 million tokens",
                "inputTokenLimit": 2097152,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-1.5-flash",
                "version": "001",
                "displayName": "Gemini 1.5 Flash",
                "description": "Fast and versatile multimodal model for scaling across diverse tasks",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-2.5-pro-preview-05-06",
                "version": "001",
                "displayName": "Gemini 2.5 Pro Preview 05-06",
                "description": "Preview version of Gemini 2.5 Pro from May 6th",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-2.5-pro-preview-06-05",
                "version": "001",
                "displayName": "Gemini 2.5 Pro Preview 06-05",
                "description": "Preview version of Gemini 2.5 Pro from June 5th",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-2.5-pro",
                "version": "001",
                "displayName": "Gemini 2.5 Pro",
                "description": "Advanced multimodal model with enhanced capabilities",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-2.5-flash-preview-05-20",
                "version": "001",
                "displayName": "Gemini 2.5 Flash Preview 05-20",
                "description": "Preview version of Gemini 2.5 Flash from May 20th",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-2.5-flash",
                "version": "001",
                "displayName": "Gemini 2.5 Flash",
                "description": "Fast and efficient multimodal model with latest improvements",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-2.0-flash",
                "version": "001",
                "displayName": "Gemini 2.0 Flash",
                "description": "Latest generation fast multimodal model",
                "inputTokenLimit": 1048576,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-2.0-flash-preview-image-generation",
                "version": "001",
                "displayName": "Gemini 2.0 Flash Preview Image Generation",
                "description": "Preview version with image generation capabilities",
                "inputTokenLimit": 32000,
                "outputTokenLimit": 8192,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent"],
                "temperature": 1.0,
                "maxTemperature": 2.0,
                "topP": 0.95,
                "topK": 64
            },
            {
                "name": "models/gemini-embedding-001",
                "version": "001",
                "displayName": "Gemini Embedding 001",
                "description": "Text embedding model for semantic similarity and search",
                "inputTokenLimit": 2048,
                "outputTokenLimit": 1,
                "supportedGenerationMethods": ["embedContent"],
                "temperature": 0.0,
                "maxTemperature": 0.0,
                "topP": 1.0,
                "topK": 1
            }
        ]
    }
    
    return Response(content=json.dumps(models_response), status_code=200, media_type="application/json; charset=utf-8")

async def proxy_request(post_data: bytes, full_path: str, username: str, method: str, query_params: dict, is_openai: bool = False, is_streaming: bool = False):
    print(f"[{method}] /{full_path} - User: {username}")
    
    creds = get_credentials()
    if not creds:
        print("❌ No credentials available")
        return Response(content="Authentication failed. Please restart the proxy to log in.", status_code=500)
    
    print(f"Using credentials - Token: {creds.token[:20] if creds.token else 'None'}..., Expired: {creds.expired}")

    if creds.expired and creds.refresh_token:
        print("Credentials expired. Refreshing...")
        try:
            from google.auth.transport.requests import Request as GoogleAuthRequest
            creds.refresh(GoogleAuthRequest())
            save_credentials(creds)
            print("Credentials refreshed successfully.")
        except Exception as e:
            print(f"Could not refresh token during request: {e}")
            return Response(content="Token refresh failed. Please restart the proxy to re-authenticate.", status_code=500)
    elif not creds.token:
        print("No access token available.")
        return Response(content="No access token. Please restart the proxy to re-authenticate.", status_code=500)

    proj_id = get_user_project_id(creds)
    if not proj_id:
        return Response(content="Failed to get user project ID.", status_code=500)
    
    onboard_user(creds, proj_id)

    if is_openai:
        target_url, final_post_data, request_headers, _ = build_gemini_request(post_data, full_path, creds, is_streaming)
    else:
        action = "streamGenerateContent" if is_streaming else "generateContent"
        target_url = f"{CODE_ASSIST_ENDPOINT}/v1internal:{action}" + "?alt=sse"
        
        try:
            incoming_json = json.loads(post_data)
        except (json.JSONDecodeError, AttributeError):
            incoming_json = {}
            
        final_post_data = json.dumps({
            "model": full_path.split('/')[2].split(':')[0],
            "project": proj_id,
            "request": incoming_json,
        })
        
        request_headers = {
            "Authorization": f"Bearer {creds.token}",
            "Content-Type": "application/json",
            "User-Agent": get_user_agent(),
        }


    if is_streaming:
        print(f"STREAMING REQUEST to: {target_url}")
        print(f"STREAMING REQUEST PAYLOAD: {final_post_data}")
        resp = requests.post(target_url, data=final_post_data, headers=request_headers, stream=True)
        print(f"STREAMING RESPONSE: {resp.status_code}")
        return handle_gemini_response(resp, is_streaming=True)
    else:
        print(f"REQUEST to: {target_url}")
        print(f"REQUEST PAYLOAD: {final_post_data}")
        resp = requests.post(target_url, data=final_post_data, headers=request_headers)
        print(f"RESPONSE: {resp.status_code}, {resp.text}")
        return handle_gemini_response(resp, is_streaming=False)

@router.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(request: Request, full_path: str, username: str = Depends(authenticate_user)):
    post_data = await request.body()
    is_streaming = "stream" in full_path
    return await proxy_request(post_data, full_path, username, request.method, dict(request.query_params), is_streaming=is_streaming)
