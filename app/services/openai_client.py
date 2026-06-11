
import logging
from functools import lru_cache

from openai import AsyncOpenAI

from app.config import get_settings

logger = logging.getLogger(__name__)


@lru_cache
def get_openai_client() -> AsyncOpenAI:
    settings = get_settings()
    logger.info("Initialising AsyncOpenAI client (model=%s)", settings.openai_model)
    return AsyncOpenAI(api_key=settings.openai_api_key)


async def chat_completion(system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
    """
    Single-turn chat helper.  Returns the assistant message content as a string.
    """
    client   = get_openai_client()
    settings = get_settings()

    response = await client.chat.completions.create(
        model=settings.openai_model,
        temperature=temperature,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
    )
    content = response.choices[0].message.content or ""
    logger.debug("LLM raw response (%d chars)", len(content))
    return content
