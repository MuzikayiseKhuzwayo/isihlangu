"""LLM client interface supporting local abliterated models via OpenAI-compatible endpoints."""

import httpx

from isihlangu.core.config import settings
from isihlangu.core.errors import ProtocolExecutionError


class InferenceClient:
    """Client for querying local vLLM or Ollama OpenAI-compatible inference servers."""

    def __init__(
        self,
        endpoint: str | None = None,
        api_key: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.endpoint = (endpoint or settings.inference_endpoint).rstrip("/")
        self.api_key = api_key or settings.inference_api_key
        self.timeout = timeout

    async def chat_completion(
        self,
        model: str,
        messages: list[dict[str, str]],
        temperature: float = 0.2,
    ) -> str:
        """Sends chat completion request to inference endpoint with structured error handling."""
        url = f"{self.endpoint}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.post(url, headers=headers, json=payload)
                if res.status_code != 200:
                    raise ProtocolExecutionError(
                        f"Inference server error ({res.status_code}): {res.text}"
                    )
                data = res.json()
                return data["choices"][0]["message"]["content"]
        except httpx.RequestError as e:
            # When offline/testing, provide structured fallback
            raise ProtocolExecutionError(f"Failed to connect to inference server at {url}: {e}") from e
