from app.models.schemas import AgentResult
from app.services.openai_service import call_openai
from app.utils.logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are PhishingAgent, an expert cybersecurity AI specializing in email phishing detection.
Analyze the provided email content for phishing indicators.
Respond ONLY with valid JSON:
{
  "risk_score": <float 0-100>,
  "findings": "<detailed explanation>",
  "confidence": <float 0.0-1.0>
}"""

async def run_phishing_agent(email_content: str) -> AgentResult:
    logger.info("PhishingAgent: analyzing email content")
    try:
        result = await call_openai(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=f"Analyze this email for phishing:\n\n{email_content}",
            temperature=0.1
        )
        return AgentResult(
            agent_name="PhishingAgent",
            risk_score=float(result.get("risk_score", 50)),
            findings=result.get("findings", "No findings."),
            confidence=float(result.get("confidence", 0.5)),
        )
    except Exception as e:
        return AgentResult(agent_name="PhishingAgent", risk_score=50.0, findings=f"Error: {str(e)}", confidence=0.0)