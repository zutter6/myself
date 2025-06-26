import os
import json
import requests
import re
import uvicorn
import base64
import platform
import time
from datetime import datetime
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import ijson
from dotenv import load_dotenv

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.auth.exceptions import RefreshError

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
CLIENT_SECRET = "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"
SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIAL_FILE = os.path.join(SCRIPT_DIR, "oauth_creds.json")
CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com"
GEMINI_PORT = int(os.getenv("GEMINI_PORT", "8888"))  # Default to 8888 if not set
GEMINI_AUTH_PASSWORD = os.getenv("GEMINI_AUTH_PASSWORD", "123456")  # Default password
CLI_VERSION = "0.1.5"  # Match current gemini-cli version

# --- Global State ---
credentials = None
user_project_id = None
onboarding_complete = False

app = FastAPI()
security = HTTPBasic()

# Add CORS middleware for preflight requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

def get_user_agent():
    """Generate User-Agent string matching gemini-cli format."""
    version = CLI_VERSION
    system = platform.system()
    arch = platform.machine()
    return f"GeminiCLI/{version} ({system}; {arch})"

def authenticate_user(request: Request):
    """Authenticate the user with multiple methods."""
    # Check for API key in query parameters first (for Gemini client compatibility)
    api_key = request.query_params.get("key")
    if api_key and api_key == GEMINI_AUTH_PASSWORD:
        return "api_key_user"
    
    # Check for API key in x-goog-api-key header (Google SDK format)
    goog_api_key = request.headers.get("x-goog-api-key", "")
    if goog_api_key and goog_api_key == GEMINI_AUTH_PASSWORD:
        return "goog_api_key_user"
    
    # Check for API key in Authorization header (Bearer token format)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        bearer_token = auth_header[7:]
        if bearer_token == GEMINI_AUTH_PASSWORD:
            return "bearer_user"
    
    # Check for HTTP Basic Authentication
    if auth_header.startswith("Basic "):
        try:
            encoded_credentials = auth_header[6:]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)
            if password == GEMINI_AUTH_PASSWORD:
                return username
        except Exception:
            pass
    
    # If none of the authentication methods work
    raise HTTPException(
        status_code=401,
        detail="Invalid authentication credentials. Use HTTP Basic Auth, Bearer token, 'key' query parameter, or 'x-goog-api-key' header.",
        headers={"WWW-Authenticate": "Basic"},
    )

# Helper class to adapt a generator of bytes into a file-like object
# that ijson can read from.
class _GeneratorStream:
    def __init__(self, generator):
        self.generator = generator
        self.buffer = b''

    def read(self, size=-1):
        # This read implementation is crucial for streaming.
        # It must not block to read the entire stream if size is -1.
        if size == -1:
            # If asked to read all, return what's in the buffer and get one more chunk.
            try:
                self.buffer += next(self.generator)
            except StopIteration:
                pass
            data = self.buffer
            self.buffer = b''
            return data

        # Otherwise, read from the generator until we have enough bytes.
        while len(self.buffer) < size:
            try:
                self.buffer += next(self.generator)
            except StopIteration:
                # Generator is exhausted.
                break
        
        data = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return data

class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    auth_code = None
    def do_GET(self):
        query_components = parse_qs(urlparse(self.path).query)
        code = query_components.get("code", [None])[0]
        if code:
            _OAuthCallbackHandler.auth_code = code
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Authentication successful!</h1><p>You can close this window and restart the proxy.</p>")
        else:
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Authentication failed.</h1><p>Please try again.</p>")

def get_platform_string():
    """Generate platform string matching gemini-cli format."""
    system = platform.system().upper()
    arch = platform.machine().upper()
    
    # Map to gemini-cli platform format
    if system == "DARWIN":
        if arch in ["ARM64", "AARCH64"]:
            return "DARWIN_ARM64"
        else:
            return "DARWIN_AMD64"
    elif system == "LINUX":
        if arch in ["ARM64", "AARCH64"]:
            return "LINUX_ARM64"
        else:
            return "LINUX_AMD64"
    elif system == "WINDOWS":
        return "WINDOWS_AMD64"
    else:
        return "PLATFORM_UNSPECIFIED"

def get_client_metadata(project_id=None):
    return {
        "ideType": "IDE_UNSPECIFIED",
        "platform": get_platform_string(),
        "pluginType": "GEMINI",
        "duetProject": project_id,
    }

def onboard_user(creds, project_id):
    """Ensures the user is onboarded, matching gemini-cli setupUser behavior."""
    global onboarding_complete
    if onboarding_complete:
        return

    # Refresh credentials if expired before making API calls
    if creds.expired and creds.refresh_token:
        print("Credentials expired. Refreshing before onboarding...")
        try:
            creds.refresh(GoogleAuthRequest())
            save_credentials(creds)
            print("Credentials refreshed successfully.")
        except Exception as e:
            print(f"Could not refresh credentials: {e}")
            raise

    print("Checking user onboarding status...")
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }
    
    # 1. Call loadCodeAssist to check current status
    load_assist_payload = {
        "cloudaicompanionProject": project_id,
        "metadata": get_client_metadata(project_id),
    }
    
    try:
        resp = requests.post(
            f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist",
            data=json.dumps(load_assist_payload),
            headers=headers,
        )
        resp.raise_for_status()
        load_data = resp.json()
        
        # Determine the tier to use (current or default)
        tier = None
        if load_data.get("currentTier"):
            tier = load_data["currentTier"]
            print("User is already onboarded.")
        else:
            # Find default tier for onboarding
            for allowed_tier in load_data.get("allowedTiers", []):
                if allowed_tier.get("isDefault"):
                    tier = allowed_tier
                    break
            
            if not tier:
                # Fallback tier if no default found (matching gemini-cli logic)
                tier = {
                    "name": "",
                    "description": "",
                    "id": "legacy-tier",
                    "userDefinedCloudaicompanionProject": True,
                }

        # Check if project ID is required but missing
        if tier.get("userDefinedCloudaicompanionProject") and not project_id:
            raise ValueError("This account requires setting the GOOGLE_CLOUD_PROJECT env var.")

        # If already onboarded, skip the onboarding process
        if load_data.get("currentTier"):
            onboarding_complete = True
            return

        print(f"Onboarding user to tier: {tier.get('name', 'legacy-tier')}")
        onboard_req_payload = {
            "tierId": tier.get("id"),
            "cloudaicompanionProject": project_id,
            "metadata": get_client_metadata(project_id),
        }

        # 2. Poll onboardUser until complete (matching gemini-cli polling logic)
        while True:
            onboard_resp = requests.post(
                f"{CODE_ASSIST_ENDPOINT}/v1internal:onboardUser",
                data=json.dumps(onboard_req_payload),
                headers=headers,
            )
            onboard_resp.raise_for_status()
            lro_data = onboard_resp.json()

            if lro_data.get("done"):
                print("Onboarding successful.")
                onboarding_complete = True
                break
            
            print("Onboarding in progress, waiting 5 seconds...")
            time.sleep(5)

    except requests.exceptions.HTTPError as e:
        print(f"Error during onboarding: {e.response.text}")
        raise

def get_user_project_id(creds):
    """Gets the user's project ID matching gemini-cli setupUser logic."""
    global user_project_id
    if user_project_id:
        return user_project_id

    # First, check for GOOGLE_CLOUD_PROJECT environment variable (matching gemini-cli)
    env_project_id = os.getenv("GOOGLE_CLOUD_PROJECT")
    if env_project_id:
        user_project_id = env_project_id
        print(f"Using project ID from GOOGLE_CLOUD_PROJECT: {user_project_id}")
        save_credentials(creds, user_project_id)
        return user_project_id

    # Second, check for GEMINI_PROJECT_ID as fallback
    gemini_env_project_id = os.getenv("GEMINI_PROJECT_ID")
    if gemini_env_project_id:
        user_project_id = gemini_env_project_id
        print(f"Using project ID from GEMINI_PROJECT_ID: {user_project_id}")
        save_credentials(creds, user_project_id)
        return user_project_id

    # Third, try to load project ID from credential file
    if os.path.exists(CREDENTIAL_FILE):
        try:
            with open(CREDENTIAL_FILE, "r") as f:
                creds_data = json.load(f)
                cached_project_id = creds_data.get("project_id")
                if cached_project_id:
                    user_project_id = cached_project_id
                    print(f"Loaded project ID from cache: {user_project_id}")
                    return user_project_id
        except Exception as e:
            print(f"Could not load project ID from cache: {e}")

    # If not found in environment or cache, probe for it via loadCodeAssist
    print("Project ID not found in environment or cache. Probing for user project ID...")
    
    # Refresh credentials if expired before making API calls
    if creds.expired and creds.refresh_token:
        print("Credentials expired. Refreshing before project ID probe...")
        try:
            creds.refresh(GoogleAuthRequest())
            save_credentials(creds)
            print("Credentials refreshed successfully.")
        except Exception as e:
            print(f"Could not refresh credentials: {e}")
            raise
    
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }
    
    probe_payload = {
        "metadata": get_client_metadata(),
    }

    try:
        resp = requests.post(
            f"{CODE_ASSIST_ENDPOINT}/v1internal:loadCodeAssist",
            data=json.dumps(probe_payload),
            headers=headers,
        )
        resp.raise_for_status()
        data = resp.json()
        user_project_id = data.get("cloudaicompanionProject")
        if not user_project_id:
            raise ValueError("Could not find 'cloudaicompanionProject' in loadCodeAssist response.")
        print(f"Successfully fetched user project ID: {user_project_id}")
        
        save_credentials(creds, user_project_id)
        print("Project ID saved to credential file for future use.")
        
        return user_project_id
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching project ID: {e.response.text}")
        raise

def save_credentials(creds, project_id=None):
    creds_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "scope": " ".join(creds.scopes) if creds.scopes else " ".join(SCOPES),
        "token_type": "Bearer",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    
    # Add expiry if available
    if creds.expiry:
        creds_data["expiry"] = creds.expiry.isoformat()
    
    # If project_id is provided, save it; otherwise preserve existing project_id
    if project_id:
        creds_data["project_id"] = project_id
    elif os.path.exists(CREDENTIAL_FILE):
        try:
            with open(CREDENTIAL_FILE, "r") as f:
                existing_data = json.load(f)
                if "project_id" in existing_data:
                    creds_data["project_id"] = existing_data["project_id"]
        except Exception:
            pass  # If we can't read existing file, just continue without project_id
    
    with open(CREDENTIAL_FILE, "w") as f:
        json.dump(creds_data, f)

def get_credentials():
    """Loads credentials matching gemini-cli OAuth2 flow."""
    global credentials
    
    # Check environment for credentials first
    env_creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if env_creds and os.path.exists(env_creds):
        try:
            with open(env_creds, "r") as f:
                creds_data = json.load(f)
            credentials = Credentials.from_authorized_user_info(creds_data, SCOPES)
            print("Loaded credentials from GOOGLE_APPLICATION_CREDENTIALS.")
            if credentials.expired and credentials.refresh_token:
                print("Refreshing expired credentials...")
                credentials.refresh(GoogleAuthRequest())
                save_credentials(credentials)
            return credentials
        except Exception as e:
            print(f"Could not load credentials from GOOGLE_APPLICATION_CREDENTIALS: {e}")

    # Fallback to cached credentials
    if os.path.exists(CREDENTIAL_FILE):
        try:
            with open(CREDENTIAL_FILE, "r") as f:
                creds_data = json.load(f)
            
            credentials = Credentials.from_authorized_user_info(creds_data, SCOPES)
            print("Loaded credentials from cache.")
            
            # Try to refresh if we have refresh token but no access token
            if not credentials.token and credentials.refresh_token:
                print("Attempting to refresh credentials...")
                try:
                    from google.auth.transport.requests import Request as AuthRequest
                    auth_request = AuthRequest()
                    credentials.refresh(auth_request)
                    print("Credentials refreshed successfully!")
                    
                    # Save refreshed credentials
                    updated_creds_data = {
                        'client_id': credentials.client_id,
                        'client_secret': credentials.client_secret,
                        'access_token': credentials.token,
                        'refresh_token': credentials.refresh_token,
                        'scope': credentials.scopes,
                        'token_type': 'Bearer',
                        'token_uri': credentials.token_uri,
                        'expiry': credentials.expiry.isoformat() if credentials.expiry else None,
                        'project_id': creds_data.get('project_id')
                    }
                    
                    with open(CREDENTIAL_FILE, 'w') as f:
                        json.dump(updated_creds_data, f, indent=2)
                    print("Refreshed credentials saved.")
                    
                except Exception as e:
                    print(f"Failed to refresh credentials: {e}")
                    return None
            
            # Check if we have a valid token after potential refresh
            if not credentials.token:
                print("No access token available after refresh attempt. Starting new login.")
                return None
                
            if credentials.expired and credentials.refresh_token:
                print("Refreshing expired credentials...")
                try:
                    credentials.refresh(GoogleAuthRequest())
                    save_credentials(credentials)
                    print("Credentials refreshed and saved.")
                except Exception as refresh_error:
                    print(f"Failed to refresh credentials: {refresh_error}. Starting new login.")
                    return None
            return credentials
        except Exception as e:
            print(f"Could not load cached credentials: {e}. Starting new login.")

    # If no valid credentials, start new login flow
    client_config = {
        "installed": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    
    # Create flow with include_granted_scopes to handle scope changes
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri="http://localhost:8080"
    )
    
    # Set include_granted_scopes to handle additional scopes gracefully
    flow.oauth2session.scope = SCOPES
    
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes='true'
    )
    print(f"\nPlease open this URL in your browser to log in:\n{auth_url}\n")
    
    server = HTTPServer(("", 8080), _OAuthCallbackHandler)
    server.handle_request()
    
    auth_code = _OAuthCallbackHandler.auth_code
    if not auth_code:
        print("Failed to retrieve authorization code.")
        return None

    # Monkey patch to handle scope validation warnings
    import oauthlib.oauth2.rfc6749.parameters
    original_validate = oauthlib.oauth2.rfc6749.parameters.validate_token_parameters
    
    def patched_validate(params):
        try:
            return original_validate(params)
        except Warning:
            # Ignore scope change warnings
            pass
    
    oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = patched_validate
    
    try:
        flow.fetch_token(code=auth_code)
        credentials = flow.credentials
        save_credentials(credentials)
        print("Authentication successful! Credentials saved.")
        return credentials
    except Exception as e:
        print(f"Authentication failed: {e}")
        return None
    finally:
        # Restore original function
        oauthlib.oauth2.rfc6749.parameters.validate_token_parameters = original_validate


@app.options("/{full_path:path}")
async def handle_preflight(request: Request, full_path: str):
    """Handle CORS preflight requests without authentication."""
    return Response(
        status_code=200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, PATCH, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )

@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy_request(request: Request, full_path: str, username: str = Depends(authenticate_user)):
    print(f"[{request.method}] /{full_path} - User: {username}")
    
    creds = get_credentials()
    if not creds:
        print("❌ No credentials available")
        return Response(content="Authentication failed. Please restart the proxy to log in.", status_code=500)

    # Check if credentials need refreshing (more lenient validation)
    if creds.expired and creds.refresh_token:
        print("Credentials expired. Refreshing...")
        try:
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

    post_data = await request.body()
    path = f"/{full_path}"
    model_name_from_url = None
    action = None

    model_match = re.match(r"/(v\d+(?:beta)?)/models/([^:]+):(\w+)", path)

    is_streaming = False
    if model_match:
        model_name_from_url = model_match.group(2)
        action = model_match.group(3)
        target_url = f"{CODE_ASSIST_ENDPOINT}/v1internal:{action}"
        if "stream" in action.lower():
            is_streaming = True
    else:
        target_url = f"{CODE_ASSIST_ENDPOINT}{path}"
    
    # Remove authentication query parameters before forwarding to Google API
    query_params = dict(request.query_params)
    # Remove our authentication parameters
    query_params.pop("key", None)
    
    # Add remaining query parameters to target URL if any
    if query_params:
        from urllib.parse import urlencode
        target_url += "?" + urlencode(query_params)

    try:
        incoming_json = json.loads(post_data)
        final_model = model_name_from_url if model_match else incoming_json.get("model")
        
        # Set default safety settings to BLOCK_NONE if not specified by user
        safety_settings = incoming_json.get("safetySettings")
        if not safety_settings:
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"}
            ]
        
        structured_payload = {
            "model": final_model,
            "project": proj_id,
            "request": {
                "contents": incoming_json.get("contents"),
                "systemInstruction": incoming_json.get("systemInstruction"),
                "cachedContent": incoming_json.get("cachedContent"),
                "tools": incoming_json.get("tools"),
                "toolConfig": incoming_json.get("toolConfig"),
                "safetySettings": safety_settings,
                "generationConfig": incoming_json.get("generationConfig"),
            },
        }
        structured_payload["request"] = {
            k: v
            for k, v in structured_payload["request"].items()
            if v is not None
        }
        final_post_data = json.dumps(structured_payload)
    except (json.JSONDecodeError, AttributeError):
        final_post_data = post_data

    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }

    if is_streaming:
        async def stream_generator():
            try:
                print(f"[STREAM] Starting streaming request to: {target_url}")
                print(f"[STREAM] Request payload size: {len(final_post_data)} bytes")
                
                # Make the initial streaming request
                resp = requests.post(target_url, data=final_post_data, headers=headers, stream=True)
                print(f"[STREAM] Response status: {resp.status_code}")
                print(f"[STREAM] Response headers: {dict(resp.headers)}")
                
                # If we get a 401, try refreshing the token and retry once
                if resp.status_code == 401 and creds.refresh_token:
                    print("[STREAM] Received 401 from Google API. Attempting to refresh token and retry...")
                    resp.close()  # Close the failed response
                    try:
                        creds.refresh(GoogleAuthRequest())
                        save_credentials(creds)
                        print("[STREAM] Token refreshed successfully. Retrying streaming request...")
                        
                        # Update headers with new token and retry
                        headers["Authorization"] = f"Bearer {creds.token}"
                        resp = requests.post(target_url, data=final_post_data, headers=headers, stream=True)
                        print(f"[STREAM] Retry request status: {resp.status_code}")
                    except Exception as e:
                        print(f"[STREAM] Could not refresh token after 401 error: {e}")
                        error_message = json.dumps({"error": {"message": "Token refresh failed after 401 error. Please restart the proxy to re-authenticate."}})
                        yield f"data: {error_message}\n\n"
                        return
                
                with resp:
                    resp.raise_for_status()
                    
                    buffer = ""
                    brace_count = 0
                    in_array = False
                    chunk_count = 0
                    total_bytes = 0
                    objects_yielded = 0
                    
                    print(f"[STREAM] Starting to process chunks...")
                    
                    for chunk in resp.iter_content(chunk_size=1024):
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode('utf-8', errors='replace')
                        chunk_count += 1
                        chunk_size = len(chunk) if chunk else 0
                        total_bytes += chunk_size
                        
                        buffer += chunk
                        
                        # Process complete JSON objects from the buffer
                        processing_iterations = 0
                        while buffer:
                            processing_iterations += 1
                            if processing_iterations > 100:  # Prevent infinite loops
                                break
                                
                            buffer = buffer.lstrip()
                            
                            if not buffer:
                                break
                                                                
                            # Handle array start
                            if buffer.startswith('[') and not in_array:
                                buffer = buffer[1:].lstrip()
                                in_array = True
                                continue
                            
                            # Handle array end
                            if buffer.startswith(']'):
                                break
                                
                            # Skip commas between objects
                            if buffer.startswith(','):
                                buffer = buffer[1:].lstrip()
                                continue
                            
                            # Look for complete JSON objects
                            if buffer.startswith('{'):
                                brace_count = 0
                                in_string = False
                                escape_next = False
                                end_pos = -1
                                
                                for i, char in enumerate(buffer):
                                    if escape_next:
                                        escape_next = False
                                        continue
                                    if char == '\\':
                                        escape_next = True
                                        continue
                                    if char == '"' and not escape_next:
                                        in_string = not in_string
                                        continue
                                    if not in_string:
                                        if char == '{':
                                            brace_count += 1
                                        elif char == '}':
                                            brace_count -= 1
                                            if brace_count == 0:
                                                end_pos = i + 1
                                                break
                                
                                if end_pos > 0:
                                    # Found complete JSON object
                                    json_str = buffer[:end_pos]
                                    buffer = buffer[end_pos:].lstrip()
                                    
                                    
                                    try:
                                        obj = json.loads(json_str)
                                        
                                        if "response" in obj:
                                            response_chunk = obj["response"]
                                            objects_yielded += 1
                                            response_json = json.dumps(response_chunk)
                                            yield f"data: {response_json}\n\n"
                                    except json.JSONDecodeError as e:
                                        continue
                                else:
                                    # Incomplete object, wait for more data
                                    break
                            else:
                                # Skip unexpected characters
                                buffer = buffer[1:]
                    
            except requests.exceptions.RequestException as e:
                print(f"Error during streaming request: {e}")
                error_message = json.dumps({"error": {"message": f"Upstream request failed: {e}"}})
                yield f"data: {error_message}\n\n"
            except Exception as e:
                print(f"An unexpected error occurred during streaming: {e}")
                error_message = json.dumps({"error": {"message": f"An unexpected error occurred: {e}"}})
                yield f"data: {error_message}\n\n"

        return StreamingResponse(stream_generator(), media_type="text/event-stream")
    else:
        # Make the request
        resp = requests.post(target_url, data=final_post_data, headers=headers)
        
        # If we get a 401, try refreshing the token and retry once
        if resp.status_code == 401 and creds.refresh_token:
            print("Received 401 from Google API. Attempting to refresh token and retry...")
            try:
                creds.refresh(GoogleAuthRequest())
                save_credentials(creds)
                print("Token refreshed successfully. Retrying request...")
                
                # Update headers with new token and retry
                headers["Authorization"] = f"Bearer {creds.token}"
                resp = requests.post(target_url, data=final_post_data, headers=headers)
                print(f"Retry request status: {resp.status_code}")
            except Exception as e:
                print(f"Could not refresh token after 401 error: {e}")
                return Response(content="Token refresh failed after 401 error. Please restart the proxy to re-authenticate.", status_code=500)
        
        if resp.status_code == 200:
            try:
                google_api_response = resp.json()
                # The actual response is nested under the "response" key
                standard_gemini_response = google_api_response.get("response")
                # Return the response object directly, not wrapped in a list
                return Response(content=json.dumps(standard_gemini_response), status_code=200, media_type="application/json")
            except (json.JSONDecodeError, AttributeError) as e:
                print(f"Error converting to standard Gemini format: {e}")
                # Fallback to sending the original content if conversion fails
                return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("Content-Type"))
        else:
            return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("Content-Type"))


if __name__ == "__main__":
    print("Initializing credentials...")
    creds = get_credentials()
    if creds:
        proj_id = get_user_project_id(creds)
        if proj_id:
            onboard_user(creds, proj_id)
        print(f"\nStarting Gemini proxy server on http://localhost:{GEMINI_PORT}")
        print("Send your Gemini API requests to this address.")
        print(f"Authentication required - Password: {GEMINI_AUTH_PASSWORD}")
        print("Use HTTP Basic Authentication with any username and the password above.")
        uvicorn.run(app, host="0.0.0.0", port=GEMINI_PORT)
    else:
        print("\nCould not obtain credentials. Please authenticate and restart the server.")