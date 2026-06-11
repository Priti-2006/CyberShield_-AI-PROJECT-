import json
from openai import AsyncOpenAI
from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

_client: AsyncOpenAI | None = None


def get_openai_client() -> AsyncOpenAI:
    global _client
    if _client is None:
        _client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
    return _client


async def call_openai(
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.2,
    max_tokens: int = 1000,
) -> dict:
    """
    Call OpenAI and return parsed JSON dict.
    The system prompt must instruct the model to return valid JSON only.
    """
    client = get_openai_client()

    try:
        response = await client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        raw = response.choices[0].message.content
        logger.debug("OpenAI raw response: %s", raw)
        return json.loads(raw)

    except json.JSONDecodeError as e:
        logger.error("Failed to parse OpenAI JSON: %s", e)
        raise ValueError(f"OpenAI returned non-JSON response: {e}") from e
    except Exception as e:
        logger.error("OpenAI API error: %s", e)
        raise
