from typing import List
from app.models.schemas import AgentResult, ScanResponse, ThreatType
from app.services.openai_service import call_openai
from app.utils.logger import get_logger

logger = get_logger(__name__)

SYSTEM_PROMPT = """You are ReasoningAgent, the final decision-making AI in CyberShield.
Respond ONLY with valid JSON:
{
  "risk_score": <float 0-100>,
  "threat_type": "<phishing|malware|scam|ransomware|impersonation|suspicious|safe|unknown>",
  "explanation": "<clear summary for non-technical user>",
  "recommendations": ["<action1>", "<action2>", "<action3>"]
}"""

async def run_reasoning_agent(agent_results: List[AgentResult]) -> ScanResponse:
    summary = "\n".join([f"[{a.agent_name}] Score:{a.risk_score} Confidence:{a.confidence}\n{a.findings}" for a in agent_results])
    try:
        result = await call_openai(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=summary,
            temperature=0.2,
            max_tokens=1200
        )
        try:
            threat_type = ThreatType(result.get("threat_type", "unknown").lower())
        except ValueError:
            threat_type = ThreatType.UNKNOWN
        return ScanResponse(
            risk_score=float(result.get("risk_score", 50)),
            threat_type=threat_type,
            explanation=result.get("explanation", "No explanation."),
            recommendations=result.get("recommendations", ["Review carefully."]),
            agent_results=agent_results
        )
    except Exception as e:
        return ScanResponse(
            risk_score=50.0,
            threat_type=ThreatType.UNKNOWN,
            explanation=f"Error: {str(e)}",
            recommendations=["Contact IT support."],
            agent_results=agent_results
        )