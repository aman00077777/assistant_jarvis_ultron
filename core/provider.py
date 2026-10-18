"""LLM Provider abstraction and Gemini implementation."""

import os
from abc import ABC, abstractmethod
from typing import Any
from google import genai
from google.genai import types


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def generate(
        self,
        messages: list[Any],
        tools: list[Any] | None = None,
    ) -> Any:
        """
        Sends messages and available tools to the LLM and returns the response.
        """
        pass


class GeminiProvider(BaseLLMProvider):
    """Gemini implementation using google-genai SDK."""

    def __init__(
        self,
        model_name: str | None = None,
        api_key: str | None = None,
    ):
        self.model_name = model_name or os.getenv("ASSISTANT_MODEL")
        if not self.model_name:
            raise ValueError("Error: ASSISTANT_MODEL environment variable set nahi hai.")

        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("Error: GEMINI_API_KEY environment variable set nahi hai.")

        # Initialize Gemini client without logging or printing keys
        self.client = genai.Client(api_key=self.api_key)

    async def generate(
        self,
        messages: list[Any],
        tools: list[Any] | None = None,
    ) -> Any:
        """
        Generates content from Gemini with automatic function calling DISABLED.
        """
        config = types.GenerateContentConfig(
            tools=tools or [],
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )
        return await self.client.aio.models.generate_content(
            model=self.model_name,
            contents=messages,
            config=config,
        )
