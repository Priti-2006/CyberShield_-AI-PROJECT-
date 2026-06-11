import logging
from abc import ABC, abstractmethod

from app.models.schemas import AgentResult

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    name: str = "BaseAgent"

    async def run(self, email_content: str | None, url: str | None) -> AgentResult:
        logger.info("[%s] starting analysis", self.name)
        try:
            result = await self._analyse(email_content, url)
            logger.info("[%s] risk_score=%.1f threat=%s", self.name, result.risk_score, result.threat_type)
            return result
        except Exception as exc:
            logger.exception("[%s] unhandled error: %s", self.name, exc)
            return AgentResult(
                agent_name=self.name,
                risk_score=0,
                threat_type="unknown",
                explanation=f"Agent encountered an error: {exc}",
            )

    @abstractmethod
    async def _analyse(self, email_content: str | None, url: str | None) -> AgentResult:
        ...
