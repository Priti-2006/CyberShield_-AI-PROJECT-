import asyncio
from typing import List
from app.models.schemas import ScanRequest, ScanResponse, AgentResult
from app.agents.phishing_agent import run_phishing_agent
from app.agents.url_agent import run_url_agent
from app.agents.threat_agent import run_threat_agent
from app.agents.reasoning_agent import run_reasoning_agent
from app.utils.logger import get_logger

logger = get_logger(__name__)

async def run_scan(request: ScanRequest) -> ScanResponse:
    tasks = []
    if request.email_content:
        tasks.append(run_phishing_agent(request.email_content))
    if request.url:
        tasks.append(run_url_agent(request.url))
    tasks.append(run_threat_agent(request.email_content, request.url))

    specialist_results: List[AgentResult] = await asyncio.gather(*tasks)
    return await run_reasoning_agent(list(specialist_results))