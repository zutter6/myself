"""
OpenAI API Routes - Handles OpenAI-compatible endpoints.
This module provides OpenAI-compatible endpoints that transform requests/responses
and delegate to the Google API client.
"""
import json
import uuid
import asyncio
import logging
from fastapi import APIRouter, Request, Response, Depends
from fastapi.responses import StreamingResponse

from .auth import authenticate_user
from .models import OpenAIChatCompletionRequest
from .openai_transformers import (
    openai_request_to_gemini,
    gemini_response_to_openai,
    gemini_stream_chunk_to_openai
)
from .google_api_client import send_gemini_request, build_gemini_payload_from_openai

router = APIRouter()


@router.post("/v1/chat/completions")
async def openai_chat_completions(
    request: OpenAIChatCompletionRequest, 
    http_request: Request, 
    username: str = Depends(authenticate_user)
):
    """
    OpenAI-compatible chat completions endpoint.
    Transforms OpenAI requests to Gemini format, sends to Google API,
    and transforms responses back to OpenAI format.
    """
    
    try:
        logging.info(f"OpenAI chat completion request: model={request.model}, stream={request.stream}")
        
        # Transform OpenAI request to Gemini format
        gemini_request_data = openai_request_to_gemini(request)
        
        # Build the payload for Google API
        gemini_payload = build_gemini_payload_from_openai(gemini_request_data)
        
    except Exception as e:
        logging.error(f"Error processing OpenAI request: {str(e)}")
        return Response(
            content=json.dumps({
                "error": {
                    "message": f"Request processing failed: {str(e)}",
                    "type": "invalid_request_error"
                }
            }),
            status_code=400,
            media_type="application/json"
        )
    
    if request.stream:
        # Handle streaming response
        async def openai_stream_generator():
            try:
                response = send_gemini_request(gemini_payload, is_streaming=True)
                
                if isinstance(response, StreamingResponse):
                    response_id = "chatcmpl-" + str(uuid.uuid4())
                    logging.info(f"Starting streaming response: {response_id}")
                    
                    async for chunk in response.body_iterator:
                        if isinstance(chunk, bytes):
                            chunk = chunk.decode('utf-8')
                        
                        if chunk.startswith('data: '):
                            try:
                                # Parse the Gemini streaming chunk
                                chunk_data = chunk[6:]  # Remove 'data: ' prefix
                                gemini_chunk = json.loads(chunk_data)
                                
                                # Transform to OpenAI format
                                openai_chunk = gemini_stream_chunk_to_openai(
                                    gemini_chunk,
                                    request.model,
                                    response_id
                                )
                                
                                # Send as OpenAI streaming format
                                yield f"data: {json.dumps(openai_chunk)}\n\n"
                                await asyncio.sleep(0)
                                
                            except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as e:
                                logging.warning(f"Failed to parse streaming chunk: {str(e)}")
                                continue
                    
                    # Send the final [DONE] marker
                    yield "data: [DONE]\n\n"
                    logging.info(f"Completed streaming response: {response_id}")
                else:
                    # Error case - log and forward the error response
                    error_msg = "Streaming request failed"
                    if hasattr(response, 'status_code'):
                        error_msg += f" (status: {response.status_code})"
                    if hasattr(response, 'body'):
                        error_msg += f" (body: {response.body})"
                    
                    logging.error(error_msg)
                    error_data = {
                        "error": {
                            "message": error_msg,
                            "type": "api_error"
                        }
                    }
                    yield f"data: {json.dumps(error_data)}\n\n"
                    yield "data: [DONE]\n\n"
            except Exception as e:
                logging.error(f"Streaming error: {str(e)}")
                error_data = {
                    "error": {
                        "message": f"Streaming failed: {str(e)}",
                        "type": "api_error"
                    }
                }
                yield f"data: {json.dumps(error_data)}\n\n"
                yield "data: [DONE]\n\n"

        return StreamingResponse(
            openai_stream_generator(), 
            media_type="text/event-stream"
        )
    
    else:
        # Handle non-streaming response
        try:
            response = send_gemini_request(gemini_payload, is_streaming=False)
            
            if isinstance(response, Response) and response.status_code != 200:
                # Log and forward error responses
                logging.error(f"Gemini API error: status={response.status_code}, body={response.body}")
                return response
            
            try:
                # Parse Gemini response and transform to OpenAI format
                gemini_response = json.loads(response.body)
                openai_response = gemini_response_to_openai(gemini_response, request.model)
                
                logging.info(f"Successfully processed non-streaming response for model: {request.model}")
                return openai_response
                
            except (json.JSONDecodeError, AttributeError) as e:
                logging.error(f"Failed to parse Gemini response: {str(e)}")
                return Response(
                    content=json.dumps({
                        "error": {
                            "message": f"Failed to process response: {str(e)}",
                            "type": "api_error"
                        }
                    }),
                    status_code=500,
                    media_type="application/json"
                )
        except Exception as e:
            logging.error(f"Non-streaming request failed: {str(e)}")
            return Response(
                content=json.dumps({
                    "error": {
                        "message": f"Request failed: {str(e)}",
                        "type": "api_error"
                    }
                }),
                status_code=500,
                media_type="application/json"
            )


@router.get("/v1/models")
async def openai_list_models(username: str = Depends(authenticate_user)):
    """
    OpenAI-compatible models endpoint.
    Returns available models in OpenAI format.
    """
    
    try:
        logging.info("OpenAI models list requested")
        
        # Convert our Gemini models to OpenAI format
        from .config import SUPPORTED_MODELS
        
        openai_models = []
        for model in SUPPORTED_MODELS:
            # Remove "models/" prefix for OpenAI compatibility
            model_id = model["name"].replace("models/", "")
            openai_models.append({
                "id": model_id,
                "object": "model",
                "created": 1677610602,  # Static timestamp
                "owned_by": "google",
                "permission": [
                    {
                        "id": "modelperm-" + model_id.replace("/", "-"),
                        "object": "model_permission",
                        "created": 1677610602,
                        "allow_create_engine": False,
                        "allow_sampling": True,
                        "allow_logprobs": False,
                        "allow_search_indices": False,
                        "allow_view": True,
                        "allow_fine_tuning": False,
                        "organization": "*",
                        "group": None,
                        "is_blocking": False
                    }
                ],
                "root": model_id,
                "parent": None
            })
        
        logging.info(f"Returning {len(openai_models)} models")
        return {
            "object": "list",
            "data": openai_models
        }
        
    except Exception as e:
        logging.error(f"Failed to list models: {str(e)}")
        return Response(
            content=json.dumps({
                "error": {
                    "message": f"Failed to list models: {str(e)}",
                    "type": "api_error"
                }
            }),
            status_code=500,
            media_type="application/json"
        )


