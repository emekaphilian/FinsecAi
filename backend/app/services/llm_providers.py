"""Provider-agnostic LLM access for FinSecAI.

Cohere is the current implementation. Additional providers can be added
without changing investigation or Copilot business logic.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
import logging
from typing import Any, Protocol

import httpx

from app.core.config import settings

SYSTEM_PROMPT = (
    "You are FinSecAI's SOC analyst assistant. Be concise and factual. "
    "Never invent transaction details not supplied in the prompt."
)
logger = logging.getLogger(__name__)


class LLMProviderError(RuntimeError):
    """Raised when the configured LLM provider cannot be used."""


class LLMProviderCredentialError(LLMProviderError):
    """Raised when a configured provider is missing required credentials."""


class LLMProvider(Protocol):
    """Provider contract used by FinSecAI application services."""

    provider_name: str
    model: str

    def generate_text(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
    ) -> str:
        ...

    def generate_structured_json(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        ...


class CohereInvestigationProvider:
    """Cohere implementation of the FinSecAI LLM provider contract."""

    provider_name = "cohere"

    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or settings.cohere_api_key
        self.model = model or settings.cohere_chat_model
        if not self.api_key:
            raise LLMProviderCredentialError("COHERE_API_KEY is not configured")
        try:
            import cohere
        except Exception as exc:  # pragma: no cover
            raise LLMProviderError("Cohere SDK is not available") from exc
        self.client = cohere.ClientV2(api_key=self.api_key)

    def _extract_text(self, response: Any) -> str:
        message = getattr(response, "message", None)

        if not message:
            raise LLMProviderError("Cohere returned no message")

        content = getattr(message, "content", None) or []
        text_blocks = [
            block.text
            for block in content
            if (
                getattr(block, "type", None) == "text"
                and getattr(block, "text", None)
            )
        ]

        if not text_blocks:
            raise LLMProviderError("Cohere returned no text content")

        return "".join(text_blocks)

    def generate_text(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
    ) -> str:
        try:
            response = self.client.chat(
                model=self.model,
                temperature=settings.cohere_temperature,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt or SYSTEM_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
            )
        except Exception as exc:
            raise LLMProviderError("Cohere chat request failed") from exc

        return self._extract_text(response)

    def generate_structured_json(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        response_format: dict[str, Any] = {"type": "json_object"}
        if response_schema:
            response_format["schema"] = response_schema
        try:
            response = self.client.chat(
                model=self.model,
                temperature=settings.cohere_temperature,
                messages=[
                    {
                        "role": "system",
                        "content": system_prompt or SYSTEM_PROMPT,
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                response_format=response_format,
            )
        except Exception as exc:
            raise LLMProviderError("Cohere structured chat request failed") from exc

        return self._extract_text(response)


class LocalOllamaProvider:
    """Local Ollama-compatible generation provider (for example, llama3.2)."""

    provider_name = "local"

    def __init__(self) -> None:
        self.model = settings.local_llm_model
        self.url = settings.local_llm_url

    def _generate(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        structured: bool = False,
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt or SYSTEM_PROMPT,
            "stream": False,
        }
        if structured:
            payload["format"] = response_schema or "json"
        try:
            response = httpx.post(
                self.url,
                json=payload,
                timeout=settings.local_llm_timeout_seconds,
            )
            response.raise_for_status()
            result = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise LLMProviderError("Local LLM request failed") from exc
        text = result.get("response")
        if not isinstance(text, str) or not text.strip():
            raise LLMProviderError("Local LLM returned no text")
        return text.strip()

    def generate_text(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
    ) -> str:
        return self._generate(prompt, system_prompt=system_prompt)

    def generate_structured_json(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        response_schema: dict[str, Any] | None = None,
    ) -> str:
        return self._generate(
            prompt,
            system_prompt=system_prompt,
            structured=True,
            response_schema=response_schema,
        )

def _create_provider(provider_name: str) -> LLMProvider:
    if provider_name == "cohere":
        return CohereInvestigationProvider()
    if provider_name in {"local", "ollama"}:
        return LocalOllamaProvider()
    raise LLMProviderError(f"Unsupported LLM provider: {provider_name}")


def get_llm_providers() -> list[LLMProvider]:
    """Build available providers in primary-then-fallback order."""
    names = [
        (getattr(settings, "llm_provider", None) or "cohere").strip().lower(),
        (getattr(settings, "llm_fallback_provider", None) or "local").strip().lower(),
    ]
    if names[0] == "cohere" and not settings.cohere_api_key:
        raise LLMProviderCredentialError("COHERE_API_KEY is not configured")

    providers: list[LLMProvider] = []
    errors: list[str] = []
    for name in dict.fromkeys(names):
        try:
            providers.append(_create_provider(name))
        except LLMProviderError as exc:
            errors.append(f"{name}: {exc}")
    if not providers:
        raise LLMProviderError(
            "No configured LLM provider is available: " + "; ".join(errors)
        )
    return providers


def get_llm_provider() -> LLMProvider:
    """Return the first available provider in primary/fallback order."""
    return get_llm_providers()[0]


async def generate(prompt: str) -> str | None:
    """Try the primary provider, then the configured backup."""
    try:
        providers = get_llm_providers()
    except LLMProviderError:
        return None
    for provider in providers:
        try:
            return await asyncio.to_thread(provider.generate_text, prompt)
        except Exception as exc:
            logger.warning("LLM provider %s failed: %s", provider.provider_name, type(exc).__name__)
    return None


async def stream(prompt: str) -> AsyncIterator[str]:
    """Return a configured-provider Copilot response without blocking the event loop.

    ``ClientV2`` is the synchronous Cohere client.  Its ``chat_stream`` method
    returns a regular iterator, so using ``async for`` on it raises before a
    response can be sent.  A normal chat request in a worker thread is more
    reliable here; the websocket still delivers the completed answer as a
    single chunk and retains its existing protocol.
    """
    try:
        providers = get_llm_providers()
    except LLMProviderError as exc:
        yield str(exc)
        return
    for provider in providers:
        try:
            answer = await asyncio.to_thread(provider.generate_text, prompt)
            if answer:
                yield answer
                return
            logger.warning("LLM provider %s returned an empty response", provider.provider_name)
        except Exception as exc:
            logger.warning("LLM provider %s failed: %s", provider.provider_name, type(exc).__name__)
    yield "All configured LLM providers are unavailable. No AI response was generated."


async def readiness() -> tuple[bool, str | None]:
    """Verify that the configured LLM provider can respond."""
    failures: list[str] = []
    try:
        providers = get_llm_providers()
    except LLMProviderError as exc:
        return False, str(exc)
    for provider in providers:
        try:
            response = await asyncio.to_thread(
                provider.generate_text,
                "Reply with exactly: ready",
                system_prompt="Reply with exactly the requested text.",
            )
            if response.strip():
                return True, None
            failures.append(f"{provider.provider_name} returned an empty response")
        except Exception as exc:
            failures.append(f"{provider.provider_name} failed ({type(exc).__name__})")
    return False, "; ".join(failures)
