import os
from typing import Any, Dict, List, Optional

import requests


class TraceTrampClient:
    def __init__(
        self,
        cage_base_url: str,
        api_key: str,
        timeout_seconds: int = 120,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("api_key is required")
        if not cage_base_url or not cage_base_url.strip():
            raise ValueError("cage_base_url is required")
        self.cage_base_url = cage_base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.session = session or requests.Session()
        self.last_headers: Dict[str, str] = {}

    def chat_completions(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not model:
            raise ValueError("model is required")
        if not messages:
            raise ValueError("messages is required")

        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
        }
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if extra:
            payload.update(extra)

        url = f"{self.cage_base_url}/v1/chat/completions"
        response = self.session.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            timeout=self.timeout_seconds,
        )
        self.last_headers = dict(response.headers)
        response.raise_for_status()
        return response.json()


def from_env() -> TraceTrampClient:
    base_url = os.environ.get("OPENAI_BASE_URL", "http://localhost:9741")
    api_key = os.environ.get("OPENAI_API_KEY", "")
    return TraceTrampClient(cage_base_url=base_url, api_key=api_key)
