"""
Pydantic models for validating Kimi API responses.

Every response from Kimi is validated before being used.
Malformed responses go to the dead-letter queue instead of crashing the forge.
"""

import json
from pydantic import BaseModel, Field, field_validator


class AlertResponse(BaseModel):
    """Validates Prompt 1 output (alert generation)."""
    alert_id: str
    timestamp: str
    severity: str
    title: str
    source_system: str
    ttp_id: str
    ttp_name: str
    difficulty: str
    raw_log: dict

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v not in ("critical", "high", "medium", "low"):
            raise ValueError(f"Invalid severity: {v}")
        return v

    @field_validator("difficulty")
    @classmethod
    def validate_difficulty(cls, v):
        if v not in ("easy", "medium", "hard", "expert"):
            raise ValueError(f"Invalid difficulty: {v}")
        return v


class InvestigationResponse(BaseModel):
    """Validates Prompt 2/3 output (investigation code)."""
    chain_of_thought: str = Field(min_length=10)
    python_code: str = Field(min_length=20)

    @field_validator("python_code")
    @classmethod
    def validate_code(cls, v):
        if "def investigate_alert" not in v:
            raise ValueError("Missing investigate_alert function definition")
        return v


class JudgeResponse(BaseModel):
    """Validates Prompt 4 output (LLM-as-Judge)."""
    is_correct: bool
    verdict_accurate: bool
    entities_complete: bool
    hallucination_detected: bool
    risk_score_appropriate: bool
    reasoning: str
    missed_indicators: list[str] = []
    fabricated_indicators: list[str] = []


class MutationResponse(BaseModel):
    """Validates Prompt 5 output (AST mutation)."""
    mutation_type: str
    mutation_description: str
    mutated_code: str

    @field_validator("mutation_type")
    @classmethod
    def validate_mutation_type(cls, v):
        valid = {"VERDICT_FLIP", "ENTITY_MISS", "MITRE_WRONG",
                 "RISK_INVERT", "CONFIDENCE_WRONG"}
        if v not in valid:
            raise ValueError(f"Invalid mutation type: {v}")
        return v

    @field_validator("mutated_code")
    @classmethod
    def validate_code(cls, v):
        if "def investigate_alert" not in v:
            raise ValueError("Missing investigate_alert function definition")
        return v


def parse_kimi_json(raw_text: str) -> dict:
    """
    Parse JSON from Kimi response, handling common formatting issues.

    Kimi sometimes wraps JSON in markdown code fences or adds preamble text.
    This function strips those before parsing.
    """
    text = raw_text.strip()

    # Strip markdown code fences
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    text = text.strip()

    # Find the first { and last } to extract JSON object
    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        text = text[first_brace:last_brace + 1]

    return json.loads(text)
