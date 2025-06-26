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
    print(f"DEBUG: Saving credentials - Token: {creds.token[:20] if creds.token else 'None'}..., Expired: {creds.expired}, Expiry: {creds.expiry}")
    
    creds_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "token": creds.token,  # Use 'token' instead of 'access_token' for consistency with Google Auth Library
        "refresh_token": creds.refresh_token,
        "scopes": creds.scopes if creds.scopes else SCOPES,  # Use 'scopes' as list instead of 'scope' as string
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    
    # Add expiry if available - ensure it's timezone-aware
    if creds.expiry:
        # Ensure the expiry is timezone-aware (UTC)
        if creds.expiry.tzinfo is None:
            from datetime import timezone
            expiry_utc = creds.expiry.replace(tzinfo=timezone.utc)
        else:
            expiry_utc = creds.expiry
        creds_data["expiry"] = expiry_utc.isoformat()
        print(f"DEBUG: Saving expiry as: {creds_data['expiry']}")
    else:
        print("DEBUG: No expiry time available to save")
    
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
    
    print(f"DEBUG: Final credential data to save: {json.dumps(creds_data, indent=2)}")
    
    with open(CREDENTIAL_FILE, "w") as f:
        json.dump(creds_data, f, indent=2)
    
    print("DEBUG: Credentials saved to file")

def get_credentials():
    """Loads credentials matching gemini-cli OAuth2 flow."""
    global credentials
    
    # First, check if we already have valid credentials in memory
    if credentials and credentials.token:
        print("Using valid credentials from memory cache.")
        print(f"DEBUG: Memory credentials - Token: {credentials.token[:20] if credentials.token else 'None'}..., Expired: {credentials.expired}, Expiry: {credentials.expiry}")
        return credentials
    else:
        print("No valid credentials in memory. Loading from disk.")
    
    # Check environment for credentials first
    env_creds = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if env_creds and os.path.exists(env_creds):
        try:
            with open(env_creds, "r") as f:
                creds_data = json.load(f)
            credentials = Credentials.from_authorized_user_info(creds_data, SCOPES)
            print("Loaded credentials from GOOGLE_APPLICATION_CREDENTIALS.")
            print(f"DEBUG: Env credentials - Token: {credentials.token[:20] if credentials.token else 'None'}..., Expired: {credentials.expired}, Expiry: {credentials.expiry}")
            return credentials
        except Exception as e:
            print(f"Could not load credentials from GOOGLE_APPLICATION_CREDENTIALS: {e}")

    # Fallback to cached credentials
    if os.path.exists(CREDENTIAL_FILE):
        try:
            with open(CREDENTIAL_FILE, "r") as f:
                creds_data = json.load(f)
            
            print(f"DEBUG: Raw credential data from file: {json.dumps(creds_data, indent=2)}")
            
            # Handle both old format (access_token) and new format (token)
            if "access_token" in creds_data and "token" not in creds_data:
                creds_data["token"] = creds_data["access_token"]
                print("DEBUG: Converted access_token to token field")
            
            # Handle both old format (scope as string) and new format (scopes as list)
            if "scope" in creds_data and "scopes" not in creds_data:
                creds_data["scopes"] = creds_data["scope"].split()
                print("DEBUG: Converted scope string to scopes list")
            
            credentials = Credentials.from_authorized_user_info(creds_data, SCOPES)
            print("Loaded credentials from cache.")
            print(f"DEBUG: Loaded credentials - Token: {credentials.token[:20] if credentials.token else 'None'}..., Expired: {credentials.expired}, Expiry: {credentials.expiry}")
            
            # Manual expiry check to avoid timezone issues
            if credentials.expiry:
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc)
                
                # Handle timezone-naive expiry by assuming it's UTC
                if credentials.expiry.tzinfo is None:
                    expiry_utc = credentials.expiry.replace(tzinfo=timezone.utc)
                else:
                    expiry_utc = credentials.expiry
                
                time_until_expiry = expiry_utc - now
                print(f"DEBUG: Current time: {now}")
                print(f"DEBUG: Token expires at: {expiry_utc}")
                print(f"DEBUG: Time until expiry: {time_until_expiry}")
                
                # Override the expired property if the token is actually still valid
                is_actually_expired = time_until_expiry.total_seconds() <= 0
                print(f"DEBUG: Token is actually expired: {is_actually_expired}")
                print(f"DEBUG: Google Auth Library says expired: {credentials.expired}")
                
                if not is_actually_expired and credentials.token:
                    print("DEBUG: Token is valid, overriding expired status")
                    # Monkey patch the expired property to return False
                    credentials._expiry = expiry_utc
                    return credentials
            
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


@app.get("/v1/models")
@app.get("/v1beta/models")
async def list_models(request: Request, username: str = Depends(authenticate_user)):
    """List available models - matching gemini-cli supported models exactly."""
    print(f"[GET] {request.url.path} - User: {username}")
    print(f"[MODELS] Serving models list (both /v1/models and /v1beta/models return the same data)")
    
    # Return all models supported by gemini-cli based on tokenLimits.ts
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
    
    print(f"Using credentials - Token: {creds.token[:20] if creds.token else 'None'}..., Expired: {creds.expired}")

    # Check if credentials need refreshing (only when expired)
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
    
    # For streaming requests, always ensure alt=sse is set
    if is_streaming:
        query_params["alt"] = "sse"
    
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

    request_headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
        "User-Agent": get_user_agent(),
    }

    if is_streaming:
        async def stream_generator():
            try:
                print(f"[STREAM] Starting streaming request to: {target_url}")
                print(f"[STREAM] Request payload size: {len(final_post_data)} bytes")
                print(f"[STREAM] Authorization header: Bearer {creds.token[:50]}...")
                print(f"[STREAM] Full headers being sent: {request_headers}")
                
                # Make the initial streaming request
                resp = requests.post(target_url, data=final_post_data, headers=request_headers, stream=True)
                print(f"[STREAM] Response status: {resp.status_code}")
                print(f"[STREAM] Response headers: {dict(resp.headers)}")
                
                # If we get a 401, try refreshing the token once
                if resp.status_code == 401:
                    print("[STREAM] Received 401 from Google API. Attempting token refresh...")
                    print(f"[STREAM] Response text: {resp.text}")
                    
                    if creds.refresh_token:
                        try:
                            creds.refresh(GoogleAuthRequest())
                            save_credentials(creds)
                            print("[STREAM] Token refreshed successfully. Retrying request...")
                            
                            # Update headers with new token
                            request_headers["Authorization"] = f"Bearer {creds.token}"
                            
                            # Retry the request with refreshed token
                            resp = requests.post(target_url, data=final_post_data, headers=request_headers, stream=True)
                            print(f"[STREAM] Retry response status: {resp.status_code}")
                            
                            if resp.status_code == 401:
                                print("[STREAM] Still getting 401 after token refresh.")
                                yield f'data: {{"error": {{"message": "Authentication failed even after token refresh. Please restart the proxy to re-authenticate."}}}}\n\n'
                                return
                        except Exception as refresh_error:
                            print(f"[STREAM] Token refresh failed: {refresh_error}")
                            yield f'data: {{"error": {{"message": "Token refresh failed. Please restart the proxy to re-authenticate."}}}}\n\n'
                            return
                    else:
                        print("[STREAM] No refresh token available.")
                        yield f'data: {{"error": {{"message": "Authentication failed. Please restart the proxy to re-authenticate."}}}}\n\n'
                        return
                
                with resp:
                    resp.raise_for_status()
                    
                    # Process exactly like the real Gemini SDK
                    print("[STREAM] Processing with Gemini SDK-compatible logic")
                    
                    # Use iter_lines() exactly like the real Gemini SDK (without decode_unicode)
                    # This should be non-blocking and yield lines as they arrive
                    for chunk in resp.iter_lines():
                        if chunk:
                            # Decode UTF-8 if it's bytes (matching SDK logic exactly)
                            if not isinstance(chunk, str):
                                chunk = chunk.decode('utf-8')
                                                        
                            # Strip 'data: ' prefix if present (matching SDK logic)
                            if chunk.startswith('data: '):
                                chunk = chunk[len('data: '):]
                                
                                try:
                                    # Parse the JSON from Google's internal API
                                    obj = json.loads(chunk)
                                    
                                    # Convert Google's internal format to standard Gemini format
                                    if "response" in obj:
                                        response_chunk = obj["response"]
                                        # Output in standard Gemini streaming format
                                        response_json = json.dumps(response_chunk, separators=(',', ':'))
                                        yield f"data: {response_json}\n\n"
                                except json.JSONDecodeError:
                                    # Skip invalid JSON
                                    continue
                    
            except requests.exceptions.RequestException as e:
                print(f"Error during streaming request: {e}")
                # Format error as real Gemini API would
                yield f'data: {{"error": {{"message": "Upstream request failed: {str(e)}"}}}}\n\n'
            except Exception as e:
                print(f"An unexpected error occurred during streaming: {e}")
                # Format error as real Gemini API would
                yield f'data: {{"error": {{"message": "An unexpected error occurred: {str(e)}"}}}}\n\n'

        # Create the streaming response with headers matching real Gemini API
        response_headers = {
            "Content-Type": "text/event-stream",
            "Content-Disposition": "attachment",
            "Vary": "Origin, X-Origin, Referer",
            "X-XSS-Protection": "0",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Server": "ESF"
        }
        
        response = StreamingResponse(
            stream_generator(),
            media_type="text/event-stream",
            headers=response_headers
        )
        
        return response
    else:
        # Make the request
        print(f"[NON-STREAM] Starting request to: {target_url}")
        print(f"[NON-STREAM] Authorization header: Bearer {creds.token[:50]}...")
        print(f"[NON-STREAM] Full headers being sent: {request_headers}")
        
        resp = requests.post(target_url, data=final_post_data, headers=request_headers)
        
        print(f"[NON-STREAM] Response status: {resp.status_code}")
        print(f"[NON-STREAM] Response headers: {dict(resp.headers)}")
        
        # If we get a 401, try refreshing the token once
        if resp.status_code == 401:
            print("Received 401 from Google API. Attempting token refresh...")
            print(f"Response text: {resp.text}")
            
            if creds.refresh_token:
                try:
                    creds.refresh(GoogleAuthRequest())
                    save_credentials(creds)
                    print("Token refreshed successfully. Retrying request...")
                    
                    # Update headers with new token
                    request_headers["Authorization"] = f"Bearer {creds.token}"
                    
                    # Retry the request with refreshed token
                    resp = requests.post(target_url, data=final_post_data, headers=request_headers)
                    print(f"Retry response status: {resp.status_code}")
                    
                    if resp.status_code == 401:
                        print("Still getting 401 after token refresh.")
                        return Response(content="Authentication failed even after token refresh. Please restart the proxy to re-authenticate.", status_code=500)
                except Exception as refresh_error:
                    print(f"Token refresh failed: {refresh_error}")
                    return Response(content="Token refresh failed. Please restart the proxy to re-authenticate.", status_code=500)
            else:
                print("No refresh token available.")
                return Response(content="Authentication failed. Please restart the proxy to re-authenticate.", status_code=500)
        
        if resp.status_code == 200:
            try:
                google_api_response = resp.json()
                # The actual response is nested under the "response" key
                standard_gemini_response = google_api_response.get("response")
                # Return the response object directly, not wrapped in a list
                return Response(content=json.dumps(standard_gemini_response), status_code=200, media_type="application/json; charset=utf-8")
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