from enum import Enum
from pydantic import BaseModel, Field, field_validator


# ── Enums ────────────────────────────────────────────────────────────────────

class ThreatType(str, Enum):
    PHISHING      = "phishing"
    MALWARE       = "malware"
    SCAM          = "scam"
    RANSOMWARE    = "ransomware"
    IMPERSONATION = "impersonation"
    CLEAN         = "clean"
    UNKNOWN       = "unknown"


class RiskLevel(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ── Request ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    email_content: str | None = Field(
        default=None,
        max_length=20_000,
        description="Raw email body / headers to analyse",
    )
    url: str | None = Field(
        default=None,
        max_length=2_048,
        description="Suspicious URL to analyse",
    )

    @field_validator("email_content", "url", mode="before")
    @classmethod
    def strip_blanks(cls, v):
        if isinstance(v, str):
            v = v.strip()
        return v or None

    def model_post_init(self, __context) -> None:
        if not self.email_content and not self.url:
            raise ValueError("Provide at least one of: email_content, url")


# ── Agent intermediate results ────────────────────────────────────────────────

class AgentResult(BaseModel):
    agent_name:  str
    risk_score:  float = Field(ge=0, le=100)
    threat_type: ThreatType
    explanation: str
    raw_output:  str = ""


# ── Final API response ────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    risk_score:      float = Field(ge=0, le=100)
    risk_level:      RiskLevel
    threat_type:     ThreatType
    explanation:     str
    recommendations: list[str]
    agent_results:   list[AgentResult] = []


class HealthResponse(BaseModel):
    status:  str
    version: str
    model:   str
