import json
import time
import uuid
from fastapi import APIRouter, Request, Response, Depends
from fastapi.responses import StreamingResponse

from .auth import authenticate_user
from .models import OpenAIChatCompletionRequest, OpenAIChatCompletionResponse, OpenAIChatCompletionStreamResponse, OpenAIChatMessage, OpenAIChatCompletionChoice, OpenAIChatCompletionStreamChoice, OpenAIDelta, GeminiRequest, GeminiContent, GeminiPart, GeminiResponse
from .gemini import proxy_request

import asyncio

router = APIRouter()

def openai_to_gemini(openai_request: OpenAIChatCompletionRequest) -> dict:
    contents = []
    for message in openai_request.messages:
        role = message.role
        if role == "assistant":
            role = "model"
        if role == "system":
            role = "user"
        if isinstance(message.content, list):
            parts = []
            for part in message.content:
                if part.get("type") == "text":
                    parts.append({"text": part.get("text", "")})
                elif part.get("type") == "image_url":
                    image_url = part.get("image_url", {}).get("url")
                    if image_url:
                        # Assuming the image_url is a base64 encoded string
                        # "data:image/jpeg;base64,{base64_image}"
                        mime_type, base64_data = image_url.split(";")
                        _, mime_type = mime_type.split(":")
                        _, base64_data = base64_data.split(",")
                        parts.append({
                            "inlineData": {
                                "mimeType": mime_type,
                                "data": base64_data
                            }
                        })
            contents.append({"role": role, "parts": parts})
        else:
            contents.append({"role": role, "parts": [{"text": message.content}]})
    
    generation_config = {}
    if openai_request.temperature is not None:
        generation_config["temperature"] = openai_request.temperature
    if openai_request.top_p is not None:
        generation_config["topP"] = openai_request.top_p
    if openai_request.max_tokens is not None:
        generation_config["maxOutputTokens"] = openai_request.max_tokens

    safety_settings = [
        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_CIVIC_INTEGRITY", "threshold": "BLOCK_NONE"}
    ]

    return {
        "contents": contents,
        "generationConfig": generation_config,
        "safetySettings": safety_settings,
        "model": openai_request.model
    }

def gemini_to_openai(gemini_response: dict, model: str) -> OpenAIChatCompletionResponse:
    choices = []
    for candidate in gemini_response.get("candidates", []):
        role = candidate.get("content", {}).get("role", "assistant")
        if role == "model":
            role = "assistant"
        choices.append(
            {
                "index": candidate.get("index"),
                "message": {
                    "role": role,
                    "content": candidate.get("content", {}).get("parts", [{}])[0].get("text"),
                },
                "finish_reason": map_finish_reason(candidate.get("finishReason")),
            }
        )
    return {
        "id": str(uuid.uuid4()),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": choices,
    }

def gemini_to_openai_stream(gemini_response: dict, model: str, response_id: str) -> dict:
    choices = []
    for candidate in gemini_response.get("candidates", []):
        role = candidate.get("content", {}).get("role", "assistant")
        if role == "model":
            role = "assistant"
        choices.append(
            {
                "index": candidate.get("index"),
                "delta": {
                    "content": candidate.get("content", {}).get("parts", [{}])[0].get("text"),
                },
                "finish_reason": map_finish_reason(candidate.get("finishReason")),
            }
        )
    return {
        "id": response_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": choices,
    }

def map_finish_reason(reason: str) -> str:
    if reason == "STOP":
        return "stop"
    elif reason == "MAX_TOKENS":
        return "length"
    elif reason in ["SAFETY", "RECITATION"]:
        return "content_filter"
    else:
        return None

@router.post("/v1/chat/completions")
async def chat_completions(request: OpenAIChatCompletionRequest, http_request: Request, username: str = Depends(authenticate_user)):
    gemini_request = openai_to_gemini(request)
    
    if request.stream:
        async def stream_generator():
            response = await proxy_request(json.dumps(gemini_request).encode('utf-8'), http_request.url.path, username, "POST", dict(http_request.query_params), is_openai=True, is_streaming=True)
            if isinstance(response, StreamingResponse):
                response_id = "chatcmpl-realstream-" + str(uuid.uuid4())
                async for chunk in response.body_iterator:
                    if chunk.startswith('data: '):
                        try:
                            data = json.loads(chunk[6:])
                            openai_response = gemini_to_openai_stream(data, request.model, response_id)
                            yield f"data: {json.dumps(openai_response)}\n\n"
                            await asyncio.sleep(0)
                        except (json.JSONDecodeError, KeyError):
                            continue
                yield "data: [DONE]\n\n"
            else:
                yield f"data: {response.body.decode()}\n\n"
                yield "data: [DONE]\n\n"

        return StreamingResponse(stream_generator(), media_type="text/event-stream")
    else:
        response = await proxy_request(json.dumps(gemini_request).encode('utf-8'), http_request.url.path, username, "POST", dict(http_request.query_params), is_openai=True, is_streaming=False)
        if isinstance(response, Response) and response.status_code != 200:
            return response
        gemini_response = json.loads(response.body)
        openai_response = gemini_to_openai(gemini_response, request.model)
        return openai_response
    

async def event_generator():
    """
    A generator function that yields a message in the Server-Sent Event (SSE)
    format every second, five times.
    """
    count = 0
    while count < 5:
        # SSE format is "data: <content>\n\n"
        # The two newlines are crucial as they mark the end of an event.
        yield "data: 1\n\n"
        
        # Log to the server console to see it working on the backend
        count += 1
        print(f"Sent chunk {count}/5")

        # Wait for 1 second
        await asyncio.sleep(1)

@router.post("/v1/test")
async def stream_data(request: OpenAIChatCompletionRequest, http_request: Request, username: str = Depends(authenticate_user)):
    """
    This endpoint returns a streaming response.
    It uses the event_generator to send data chunks.
    The media_type is 'text/event-stream' which is standard for SSE.
    """
    return StreamingResponse(event_generator(), media_type="text/event-stream")
