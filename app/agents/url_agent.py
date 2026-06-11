from app.models.schemas import AgentResult
from app.services.openai_service import call_openai
from app.utils.logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are URLAgent, an expert cybersecurity AI specializing in malicious URL detection.
Respond ONLY with valid JSON:
{
  "risk_score": <float 0-100>,
  "findings": "<detailed explanation>",
  "confidence": <float 0.0-1.0>
}"""

async def run_url_agent(url: str) -> AgentResult:
    logger.info("URLAgent: analyzing URL")
    try:
        result = await call_openai(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=f"Analyze this URL:\n\n{url}",
            temperature=0.1
        )
        return AgentResult(
            agent_name="URLAgent",
            risk_score=float(result.get("risk_score", 50)),
            findings=result.get("findings", "No findings."),
            confidence=float(result.get("confidence", 0.5)),
        )
    except Exception as e:
        return AgentResult(agent_name="URLAgent", risk_score=50.0, findings=f"Error: {str(e)}", confidence=0.0)