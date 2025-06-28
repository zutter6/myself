from pydantic import BaseModel, Field
from typing import List, Optional, Union, Dict, Any

# OpenAI Models
class OpenAIChatMessage(BaseModel):
    role: str
    content: Union[str, List[Dict[str, Any]]]

class OpenAIChatCompletionRequest(BaseModel):
    model: str
    messages: List[OpenAIChatMessage]
    stream: bool = False
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    max_tokens: Optional[int] = None

class OpenAIChatCompletionChoice(BaseModel):
    index: int
    message: OpenAIChatMessage
    finish_reason: Optional[str] = None

class OpenAIChatCompletionResponse(BaseModel):
    id: str
    object: str
    created: int
    model: str
    choices: List[OpenAIChatCompletionChoice]

class OpenAIDelta(BaseModel):
    content: Optional[str] = None

class OpenAIChatCompletionStreamChoice(BaseModel):
    index: int
    delta: OpenAIDelta
    finish_reason: Optional[str] = None

class OpenAIChatCompletionStreamResponse(BaseModel):
    id: str
    object: str
    created: int
    model: str
    choices: List[OpenAIChatCompletionStreamChoice]

# Gemini Models
class GeminiPart(BaseModel):
    text: str

class GeminiContent(BaseModel):
    role: str
    parts: List[GeminiPart]

class GeminiRequest(BaseModel):
    contents: List[GeminiContent]

class GeminiCandidate(BaseModel):
    content: GeminiContent
    finish_reason: Optional[str] = None
    index: int

class GeminiResponse(BaseModel):
    candidates: List[GeminiCandidate]