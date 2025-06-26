# Gemini CLI to API Proxy

A proxy server that converts Google's Gemini CLI authentication to standard API format, allowing you to use Gemini models with any Gemini API client.

## Features

- OAuth 2.0 authentication with Google Cloud
- Automatic project ID detection and caching
- Support for both streaming and non-streaming requests
- Converts Google's internal API format to standard Gemini API format
- Credential caching for seamless restarts

## Prerequisites

- Python 3.7 or higher
- Google Cloud account with Gemini API access
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone or download this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Setup and Usage

### First Time Setup

1. **(Optional) Configure your settings:**
   If you know your Google Cloud project ID, you can set it in the `.env` file to skip automatic detection:
   ```bash
   # Edit the .env file
   GEMINI_PROJECT_ID=your-project-id
   
   # Optional: Change the default port
   GEMINI_PORT=8888
   ```

2. **Start the proxy server:**
   ```bash
   python gemini_proxy.py
   ```

3. **Authenticate with Google:**
   - On first run, the proxy will display an authentication URL
   - Open the URL in your browser and sign in with your Google account
   - Grant the necessary permissions
   - The browser will show "Authentication successful!" when complete
   - The proxy will automatically save your credentials for future use

4. **Project ID Detection:**
   - If `GEMINI_PROJECT_ID` is set in the `.env` file, it will be used
   - Otherwise, the proxy will automatically detect and cache your Google Cloud project ID
   - This only happens once - subsequent runs will use the cached project ID

### Regular Usage

After initial setup, simply run:
```bash
python gemini_proxy.py
```

The proxy server will start on `http://localhost:8888` and display:
```
Starting Gemini proxy server on http://localhost:8888
Send your Gemini API requests to this address.
```

### Using with API Clients

Configure your Gemini API client to use `http://localhost:8888` as the base URL. The proxy accepts standard Gemini API requests and handles the authentication automatically.

Example request:
```bash
curl -X POST "http://localhost:8888/v1/models/gemini-pro:generateContent?key=123456" \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [{
      "parts": [{"text": "Hello, how are you?"}]
    }]
  }'
```

**Note:** The proxy supports multiple authentication methods. The `key` query parameter is the most compatible with standard Gemini clients.

### Safety Settings

The proxy automatically sets default safety settings to `BLOCK_NONE` for all categories if no safety settings are specified in the request. This provides maximum flexibility for content generation. The default categories are:

- `HARM_CATEGORY_HARASSMENT`
- `HARM_CATEGORY_HATE_SPEECH`
- `HARM_CATEGORY_SEXUALLY_EXPLICIT`
- `HARM_CATEGORY_DANGEROUS_CONTENT`

You can override these defaults by including your own `safetySettings` in the request payload.

## Authentication

The proxy supports multiple authentication methods for maximum compatibility:

- **Default Password:** `123456`
- **Configuration:** Set `GEMINI_AUTH_PASSWORD` in `.env` file to change the password

### Authentication Methods

1. **API Key (Query Parameter)** - Compatible with standard Gemini clients:
   ```bash
   curl -X POST "http://localhost:8888/v1/models/gemini-pro:generateContent?key=123456" \
     -H "Content-Type: application/json" \
     -d '{"contents": [{"parts": [{"text": "Hello!"}]}]}'
   ```

2. **Bearer Token** - Standard API token format:
   ```bash
   curl -X POST http://localhost:8888/v1/models/gemini-pro:generateContent \
     -H "Authorization: Bearer 123456" \
     -H "Content-Type: application/json" \
     -d '{"contents": [{"parts": [{"text": "Hello!"}]}]}'
   ```

3. **HTTP Basic Authentication** - Traditional username/password:
   ```bash
   curl -u "user:123456" -X POST http://localhost:8888/v1/models/gemini-pro:generateContent \
     -H "Content-Type: application/json" \
     -d '{"contents": [{"parts": [{"text": "Hello!"}]}]}'
   ```

**Python examples:**
```python
import requests
from requests.auth import HTTPBasicAuth

# Method 1: Query parameter
response = requests.post(
    "http://localhost:8888/v1/models/gemini-pro:generateContent?key=123456",
    json={"contents": [{"parts": [{"text": "Hello!"}]}]}
)

# Method 2: Bearer token
response = requests.post(
    "http://localhost:8888/v1/models/gemini-pro:generateContent",
    headers={"Authorization": "Bearer 123456"},
    json={"contents": [{"parts": [{"text": "Hello!"}]}]}
)

# Method 3: Basic auth
response = requests.post(
    "http://localhost:8888/v1/models/gemini-pro:generateContent",
    auth=HTTPBasicAuth("user", "123456"),
    json={"contents": [{"parts": [{"text": "Hello!"}]}]}
)
```

## Configuration

The proxy uses the following configuration:
- **Port:** 8888 (default, configurable via `.env`)
- **Credential file:** `oauth_creds.json` (automatically created)
- **Configuration file:** `.env` (optional settings)
- **Scopes:** Cloud Platform, User Info (email/profile), OpenID

### Configuration File (.env)

You can create a `.env` file in the same directory as the script to configure the proxy:

```bash
# Set your Google Cloud Project ID to skip automatic detection
GEMINI_PROJECT_ID=my-gcp-project-123

# Set a custom port (default is 8888)
GEMINI_PORT=9000

# Set authentication password (default is 123456)
GEMINI_AUTH_PASSWORD=your-secure-password
```

**Note:** The `.env` file is automatically excluded from version control via `.gitignore`.

## File Structure

- `gemini_proxy.py` - Main proxy server
- `oauth_creds.json` - Cached OAuth credentials and project ID (auto-generated)
- `requirements.txt` - Python dependencies
- `.env` - Configuration file (optional, create as needed)
- `.gitignore` - Prevents credential and config files from being committed

## Troubleshooting

### Port Already in Use
If you see "error while attempting to bind on address", another instance is already running. Stop the existing process or use a different port.

### Authentication Issues (Google OAuth)
- Delete `oauth_creds.json` and restart to re-authenticate
- Ensure your Google account has access to Google Cloud and Gemini API
- Check that the required scopes are granted during authentication

### Authentication Issues (Proxy Access)
- If you get 401 Unauthorized errors, check your authentication method
- Default password is `123456` unless changed in `.env` file
- Try different authentication methods:
  - Query parameter: `?key=123456`
  - Bearer token: `Authorization: Bearer 123456`
  - Basic auth: `Authorization: Basic base64(user:123456)`
- Most Gemini clients work best with the query parameter method (`?key=password`)

### Project ID Issues
- The proxy automatically detects your project ID on first run
- If detection fails, you can manually set `GEMINI_PROJECT_ID` in the `.env` file
- Check your Google Cloud project permissions if auto-detection fails
- Delete `oauth_creds.json` to force re-detection
- Project ID in `.env` file takes priority over cached and auto-detected project IDs

## Security Notes

- **Never commit `oauth_creds.json`** - it contains sensitive authentication tokens
- The `.gitignore` file is configured to prevent accidental commits
- Credentials are stored locally and refreshed automatically when expired
- The proxy runs on localhost only for security

## API Compatibility

This proxy converts between:
- **Input:** Standard Gemini API format
- **Output:** Standard Gemini API responses
- **Internal:** Google's Cloud Code Assist API format

The conversion is transparent to API clients.