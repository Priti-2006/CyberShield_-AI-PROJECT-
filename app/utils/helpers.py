import json
import logging
import re

logger = logging.getLogger(__name__)


def parse_json_from_llm(text: str) -> dict:
    """
    Robustly extract the first JSON object from an LLM response,
    even when it is wrapped in markdown fences.
    """
    # Strip ```json ... ``` fences
    text = re.sub(r"```(?:json)?", "", text).strip().rstrip("`").strip()

    # Find the first {...} block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        logger.warning("No JSON object found in LLM output:\n%s", text)
        return {}

    try:
        return json.loads(match.group())
    except json.JSONDecodeError as exc:
        logger.error("JSON parse error: %s\nRaw text:\n%s", exc, text)
        return {}


def clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def risk_level_from_score(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"
