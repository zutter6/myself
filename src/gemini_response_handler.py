import json
import requests
from fastapi import Response
from fastapi.responses import StreamingResponse
import asyncio

def handle_gemini_response(resp, is_streaming):
    if is_streaming:
        async def stream_generator():
            try:
                with resp:
                    resp.raise_for_status()
                    
                    print("[STREAM] Processing with Gemini SDK-compatible logic")
                    
                    for chunk in resp.iter_lines():
                        if chunk:
                            if not isinstance(chunk, str):
                                chunk = chunk.decode('utf-8')
                                
                            print(chunk)
                                                        
                            if chunk.startswith('data: '):
                                chunk = chunk[len('data: '):]
                                
                                try:
                                    obj = json.loads(chunk)
                                    
                                    if "response" in obj:
                                        response_chunk = obj["response"]
                                        response_json = json.dumps(response_chunk, separators=(',', ':'))
                                        response_line = f"data: {response_json}\n\n"
                                        yield response_line
                                        await asyncio.sleep(0)
                                except json.JSONDecodeError:
                                    continue
                    
            except requests.exceptions.RequestException as e:
                print(f"Error during streaming request: {e}")
                yield f'data: {{"error": {{"message": "Upstream request failed: {str(e)}"}}}}\n\n'.encode('utf-8')
            except Exception as e:
                print(f"An unexpected error occurred during streaming: {e}")
                yield f'data: {{"error": {{"message": "An unexpected error occurred: {str(e)}"}}}}\n\n'.encode('utf-8')

        response_headers = {
            "Content-Type": "text/event-stream",
            "Content-Disposition": "attachment",
            "Vary": "Origin, X-Origin, Referer",
            "X-XSS-Protection": "0",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
            "Server": "ESF"
        }
        
        return StreamingResponse(
            stream_generator(),
            media_type="text/event-stream",
            headers=response_headers
        )
    else:
        if resp.status_code == 200:
            try:
                google_api_response = resp.text
                if google_api_response.startswith('data: '):
                    google_api_response = google_api_response[len('data: '):]
                google_api_response = json.loads(google_api_response)
                standard_gemini_response = google_api_response.get("response")
                return Response(content=json.dumps(standard_gemini_response), status_code=200, media_type="application/json; charset=utf-8")
            except (json.JSONDecodeError, AttributeError) as e:
                print(f"Error converting to standard Gemini format: {e}")
                return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("Content-Type"))
        else:
            return Response(content=resp.content, status_code=resp.status_code, media_type=resp.headers.get("Content-Type"))