from typing import Optional
from app.models.schemas import AgentResult
from app.services.openai_service import call_openai
from app.utils.logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are ThreatAgent, classifying cyber threats.
Respond ONLY with valid JSON:
{
  "threat_type": "<phishing|malware|scam|ransomware|impersonation|suspicious|safe>",
  "risk_score": <float 0-100>,
  "findings": "<explanation>",
  "confidence": <float 0.0-1.0>
}"""

async def run_threat_agent(email_content: Optional[str], url: Optional[str]) -> AgentResult:
    parts = []
    if email_content:
        parts.append(f"EMAIL:\n{email_content}")
    if url:
        parts.append(f"URL:\n{url}")
    try:
        result = await call_openai(
            system_prompt=SYSTEM_PROMPT,
            user_prompt="\n\n".join(parts),
            temperature=0.1
        )
        return AgentResult(
            agent_name="ThreatAgent",
            risk_score=float(result.get("risk_score", 50)),
            findings=result.get("findings", "No findings."),
            confidence=float(result.get("confidence", 0.5)),
        )
    except Exception as e:
        return AgentResult(agent_name="ThreatAgent", risk_score=50.0, findings=f"Error: {str(e)}", confidence=0.0)