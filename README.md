# Gemini CLI to API Proxy

A proxy server that converts Google's Gemini CLI authentication to standard API format, allowing you to use Gemini models with any OpenAI-compatible client.

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

1. **Start the proxy server:**
   ```bash
   python gemini_proxy.py
   ```

2. **Authenticate with Google:**
   - On first run, the proxy will display an authentication URL
   - Open the URL in your browser and sign in with your Google account
   - Grant the necessary permissions
   - The browser will show "Authentication successful!" when complete
   - The proxy will automatically save your credentials for future use

3. **Project ID Detection:**
   - The proxy will automatically detect and cache your Google Cloud project ID
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
curl -X POST http://localhost:8888/v1/models/gemini-pro:generateContent \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [{
      "parts": [{"text": "Hello, how are you?"}]
    }]
  }'
```

## Configuration

The proxy uses the following configuration:
- **Port:** 8888 (hardcoded)
- **Credential file:** `oauth_creds.json` (automatically created)
- **Scopes:** Cloud Platform, User Info (email/profile), OpenID

## File Structure

- `gemini_proxy.py` - Main proxy server
- `oauth_creds.json` - Cached OAuth credentials and project ID (auto-generated)
- `requirements.txt` - Python dependencies
- `.gitignore` - Prevents credential files from being committed

## Troubleshooting

### Port Already in Use
If you see "error while attempting to bind on address", another instance is already running. Stop the existing process or use a different port.

### Authentication Issues
- Delete `oauth_creds.json` and restart to re-authenticate
- Ensure your Google account has access to Google Cloud and Gemini API
- Check that the required scopes are granted during authentication

### Project ID Issues
- The proxy automatically detects your project ID on first run
- If detection fails, check your Google Cloud project permissions
- Delete `oauth_creds.json` to force re-detection

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