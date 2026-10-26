"""Pydantic models: they validate incoming JSON and describe outgoing JSON."""
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app import config


class ScanRequest(BaseModel):
    prompt: str = Field(..., max_length=config.MAX_PROMPT_LENGTH, description="The prompt to scan")

    @field_validator("prompt")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Prompt must not be empty")
        return value


class RuleMatch(BaseModel):
    rule_id: str
    category: str
    category_label: str
    weight: float
    description: str
    evidence: str
    source: str


class MlGuess(BaseModel):
    label: str
    probability: float


class ScanResult(BaseModel):
    scan_id: int
    risk_score: int
    verdict: str
    category: str
    category_label: str
    rule_score: float
    ml_score: Optional[float] = None
    ml_available: bool
    confidence: str
    uncertainty_note: Optional[str] = None
    matched_rules: list[RuleMatch]
    normalization_notes: list[str]
    ml_top: list[MlGuess]
    explanation: str
    thresholds: dict
    disclaimer: str


class RecentEvent(BaseModel):
    id: int
    created_at: datetime
    prompt_preview: str
    risk_score: int
    category_label: str
    verdict: str
    source: str


class StatsResponse(BaseModel):
    total: int
    allowed: int
    suspicious: int
    blocked: int
    block_rate: float
    categories: list[dict]
    risk_distribution: list[dict]
    daily: list[dict]
    recent: list[RecentEvent]


class LogItem(RecentEvent):
    explanation: str
    prompt_length: int


class LogsResponse(BaseModel):
    total: int
    items: list[LogItem]


class SimulatorRequest(BaseModel):
    example_id: Optional[str] = None
    prompt: Optional[str] = Field(default=None, max_length=config.MAX_PROMPT_LENGTH)

    @model_validator(mode="after")
    def need_one(self):
        if not self.example_id and not (self.prompt and self.prompt.strip()):
            raise ValueError("Provide either example_id or prompt")
        return self


class AgentReply(BaseModel):
    status: str                      # replied / blocked / needs_confirmation
    reply: str


class SimulatorResponse(BaseModel):
    title: str
    prompt: str
    expected: str                    # what the example is *meant* to be (safe / attack / borderline)
    matches_expectation: bool
    scan: ScanResult
    unprotected: AgentReply
    protected: AgentReply


class ChatRequest(BaseModel):
    message: str = Field(..., max_length=config.MAX_PROMPT_LENGTH)
    protected: bool = True
    confirm: bool = False            # user confirmed sending a SUSPICIOUS prompt

    @field_validator("message")
    @classmethod
    def not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Message must not be empty")
        return value


class ChatResponse(BaseModel):
    status: str
    reply: str
    protected: bool
    scan: Optional[ScanResult] = None
