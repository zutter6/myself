import os
import json
import requests
import re
import uvicorn
from datetime import datetime
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import ijson

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleAuthRequest

# --- Configuration ---
CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
CLIENT_SECRET = "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"
SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
]
GEMINI_DIR = os.path.dirname(os.path.abspath(__file__))  # Same directory as the script
CREDENTIAL_FILE = os.path.join(GEMINI_DIR, "oauth_creds.json")
CODE_ASSIST_ENDPOINT = "https://cloudcode-pa.googleapis.com"

# --- Global State ---
credentials = None
user_project_id = None

app = FastAPI()

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

def get_user_project_id(creds):
    """Gets the user's project ID from cache or by probing the API."""
    global user_project_id
    if user_project_id:
        return user_project_id

    # First, try to load project ID from credential file
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

    # If not found in cache, probe for it
    print("Project ID not found in cache. Probing for user project ID...")
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "Content-Type": "application/json",
    }
    
    probe_payload = {
        "cloudaicompanionProject": "gcp-project",
        "metadata": {
            "ideType": "VSCODE",
            "pluginType": "GEMINI"
        }
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
        
        # Save the project ID to the credential file for future use
        save_credentials(creds, user_project_id)
        print("Project ID saved to credential file for future use.")
        
        return user_project_id
    except requests.exceptions.HTTPError as e:
        print(f"Error fetching project ID: {e.response.text}")
        raise

def save_credentials(creds, project_id=None):
    os.makedirs(GEMINI_DIR, exist_ok=True)
    creds_data = {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "scope": " ".join(creds.scopes),
        "token_type": "Bearer",
        "expiry_date": creds.expiry.isoformat() if creds.expiry else None,
    }
    
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
    """Loads credentials from cache or initiates the OAuth 2.0 flow."""
    global credentials

    if credentials:
        if credentials.valid:
            return credentials
        if credentials.expired and credentials.refresh_token:
            print("Refreshing expired credentials...")
            try:
                credentials.refresh(GoogleAuthRequest())
                save_credentials(credentials)
                print("Credentials refreshed successfully.")
                return credentials
            except Exception as e:
                print(f"Could not refresh token: {e}. Attempting to load from file.")
    
    if os.path.exists(CREDENTIAL_FILE):
        try:
            with open(CREDENTIAL_FILE, "r") as f:
                creds_data = json.load(f)

            # Load project ID if available
            global user_project_id
            cached_project_id = creds_data.get("project_id")
            if cached_project_id:
                user_project_id = cached_project_id
                print(f"Loaded project ID from credential file: {user_project_id}")

            expiry = None
            expiry_str = creds_data.get("expiry_date")
            if expiry_str:
                if not isinstance(expiry_str, str) or not expiry_str.strip():
                     expiry = None
                elif expiry_str.endswith('Z'):
                    expiry_str = expiry_str[:-1] + '+00:00'
                    expiry = datetime.fromisoformat(expiry_str)
                else:
                    expiry = datetime.fromisoformat(expiry_str)

            credentials = Credentials(
                token=creds_data.get("access_token"),
                refresh_token=creds_data.get("refresh_token"),
                token_uri="https://oauth2.googleapis.com/token",
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                scopes=SCOPES,
                expiry=expiry
            )
            
            if credentials.expired and credentials.refresh_token:
                print("Loaded credentials from file are expired. Refreshing...")
                credentials.refresh(GoogleAuthRequest())
                save_credentials(credentials)

            print("Successfully loaded credentials from cache.")
            return credentials
        except Exception as e:
            print(f"Could not load cached credentials: {e}. Starting new login.")

    client_config = {
        "installed": {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    flow = Flow.from_client_config(
        client_config, scopes=SCOPES, redirect_uri="http://localhost:8080"
    )
    auth_url, _ = flow.authorization_url(access_type="offline", prompt="consent")
    print(f"\nPlease open this URL in your browser to log in:\n{auth_url}\n")
    
    server = HTTPServer(("", 8080), _OAuthCallbackHandler)
    server.handle_request()
    
    auth_code = _OAuthCallbackHandler.auth_code
    if not auth_code:
        print("Failed to retrieve authorization code.")
        return None

    flow.fetch_token(code=auth_code)
    credentials = flow.credentials
    save_credentials(credentials)
    print("Authentication successful! Credentials saved.")
    return credentials


@app.post("/{full_path:path}")
async def proxy_request(request: Request, full_path: str):
    creds = get_credentials()
    if not creds:
        return Response(content="Authentication failed. Please restart the proxy to log in.", status_code=500)

    proj_id = get_user_project_id(creds)
    if not proj_id:
        return Response(content="Failed to get user project ID.", status_code=500)

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

    try:
        incoming_json = json.loads(post_data)
        final_model = model_name_from_url if model_match else incoming_json.get("model")
        
        structured_payload = {
            "model": final_model,
            "project": proj_id,
            "request": {
                "contents": incoming_json.get("contents"),
                "systemInstruction": incoming_json.get("systemInstruction"),
                "cachedContent": incoming_json.get("cachedContent"),
                "tools": incoming_json.get("tools"),
                "toolConfig": incoming_json.get("toolConfig"),
                "safetySettings": incoming_json.get("safetySettings"),
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
        # We remove 'Accept-Encoding' to allow the server to send gzip,
        # which it seems to stream correctly. We will decompress on the fly.
    }

    if is_streaming:
        async def stream_generator():
            try:
                print(f"[STREAM] Starting streaming request to: {target_url}")
                print(f"[STREAM] Request payload size: {len(final_post_data)} bytes")
                
                with requests.post(target_url, data=final_post_data, headers=headers, stream=True) as resp:
                    print(f"[STREAM] Response status: {resp.status_code}")
                    print(f"[STREAM] Response headers: {dict(resp.headers)}")
                    resp.raise_for_status()
                    
                    buffer = ""
                    brace_count = 0
                    in_array = False
                    chunk_count = 0
                    total_bytes = 0
                    objects_yielded = 0
                    
                    print(f"[STREAM] Starting to process chunks...")
                    
                    for chunk in resp.iter_content(chunk_size=1024, decode_unicode=True):
                        chunk_count += 1
                        chunk_size = len(chunk) if chunk else 0
                        total_bytes += chunk_size
                        
                        print(f"[STREAM] Chunk #{chunk_count}: {chunk_size} bytes, total: {total_bytes} bytes")
                        if chunk:
                            print(f"[STREAM] Chunk content preview: {repr(chunk[:100])}")
                        
                        buffer += chunk
                        print(f"[STREAM] Buffer size after chunk: {len(buffer)} chars")
                        
                        # Process complete JSON objects from the buffer
                        processing_iterations = 0
                        while buffer:
                            processing_iterations += 1
                            if processing_iterations > 100:  # Prevent infinite loops
                                print(f"[STREAM] WARNING: Too many processing iterations, breaking")
                                break
                                
                            buffer = buffer.lstrip()
                            
                            if not buffer:
                                print(f"[STREAM] Buffer empty after lstrip")
                                break
                                
                            print(f"[STREAM] Processing buffer (len={len(buffer)}): {repr(buffer[:50])}")
                                
                            # Handle array start
                            if buffer.startswith('[') and not in_array:
                                print(f"[STREAM] Found array start, entering array mode")
                                buffer = buffer[1:].lstrip()
                                in_array = True
                                continue
                            
                            # Handle array end
                            if buffer.startswith(']'):
                                print(f"[STREAM] Found array end, stopping processing")
                                break
                                
                            # Skip commas between objects
                            if buffer.startswith(','):
                                print(f"[STREAM] Skipping comma separator")
                                buffer = buffer[1:].lstrip()
                                continue
                            
                            # Look for complete JSON objects
                            if buffer.startswith('{'):
                                print(f"[STREAM] Found object start, parsing JSON object...")
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
                                    
                                    print(f"[STREAM] Found complete JSON object ({len(json_str)} chars): {repr(json_str[:200])}")
                                    
                                    try:
                                        obj = json.loads(json_str)
                                        print(f"[STREAM] Successfully parsed JSON object with keys: {list(obj.keys())}")
                                        
                                        if "response" in obj:
                                            response_chunk = obj["response"]
                                            objects_yielded += 1
                                            response_json = json.dumps(response_chunk)
                                            print(f"[STREAM] Yielding object #{objects_yielded} (response size: {len(response_json)} chars)")
                                            print(f"[STREAM] Response content preview: {repr(response_json[:200])}")
                                            yield f"data: {response_json}\n\n"
                                        else:
                                            print(f"[STREAM] Object has no 'response' key, skipping")
                                    except json.JSONDecodeError as e:
                                        print(f"[STREAM] Failed to parse JSON object: {e}")
                                        print(f"[STREAM] Problematic JSON: {repr(json_str[:500])}")
                                        continue
                                else:
                                    # Incomplete object, wait for more data
                                    print(f"[STREAM] Incomplete JSON object (brace_count={brace_count}), waiting for more data")
                                    break
                            else:
                                # Skip unexpected characters
                                print(f"[STREAM] Skipping unexpected character: {repr(buffer[0])}")
                                buffer = buffer[1:]
                    
                    print(f"[STREAM] Finished processing. Total chunks: {chunk_count}, total bytes: {total_bytes}, objects yielded: {objects_yielded}")

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
        resp = requests.post(target_url, data=final_post_data, headers=headers)
        if resp.status_code == 200:
            try:
                google_api_response = resp.json()
                # The actual response is nested under the "response" key
                # The actual response is nested under the "response" key
                standard_gemini_response = google_api_response.get("response")
                # The standard client expects a list containing the response object
                return Response(content=json.dumps([standard_gemini_response]), status_code=200, media_type="application/json")
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
        get_user_project_id(creds)
        print("\nStarting Gemini proxy server on http://localhost:8888")
        print("Send your Gemini API requests to this address.")
        uvicorn.run(app, host="0.0.0.0", port=8888)
    else:
        print("\nCould not obtain credentials. Please authenticate and restart the server.")