import logging
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from .gemini_routes import router as gemini_router
from .openai_routes import router as openai_router
from .auth import get_credentials, get_user_project_id, onboard_user

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

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
    try:
        logging.info("Starting Gemini proxy server...")
        creds = get_credentials()
        if creds:
            try:
                proj_id = get_user_project_id(creds)
                if proj_id:
                    onboard_user(creds, proj_id)
                    logging.info(f"Successfully onboarded with project ID: {proj_id}")
                logging.info("Gemini proxy server started successfully")
                logging.info("Authentication required - Password: see .env file")
            except Exception as e:
                logging.error(f"Setup failed: {str(e)}")
                logging.warning("Server started but may not function properly until setup issues are resolved.")
        else:
            logging.error("Could not obtain credentials. Please authenticate and restart the server.")
    except Exception as e:
        logging.error(f"Startup error: {str(e)}")
        logging.warning("Server may not function properly.")

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

# Health check endpoint for Docker/Hugging Face
@app.get("/health")
async def health_check():
    """Health check endpoint for container orchestration."""
    return {"status": "healthy", "service": "geminicli2api"}

app.include_router(openai_router)
app.include_router(gemini_router)