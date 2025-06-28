from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from .gemini import router as gemini_router
from .openai import router as openai_router
from .auth import get_credentials, get_user_project_id, onboard_user

app = FastAPI()

# Add CORS middleware for preflight requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)

@app.on_event("startup")
async def startup_event():
    print("Initializing credentials...")
    creds = get_credentials()
    if creds:
        proj_id = get_user_project_id(creds)
        if proj_id:
            onboard_user(creds, proj_id)
        print(f"\nStarting Gemini proxy server")
        print("Send your Gemini API requests to this address.")
        print(f"Authentication required - Password: see .env file")
        print("Use HTTP Basic Authentication with any username and the password above.")
    else:
        print("\nCould not obtain credentials. Please authenticate and restart the server.")

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

app.include_router(openai_router)
app.include_router(gemini_router)