"""
Pydantic Models for ScamGuard AI API
Defines request/response schemas for scam analysis endpoints
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Union, Dict, Any
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk level classification for scam analysis"""
    SAFE = "SAFE"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AgentState(str, Enum):
    """FSM states for honey-pot conversation strategy"""
    CONFUSE = "CONFUSE"
    DELAY = "DELAY"
    EXTRACT = "EXTRACT"
    SAFE_EXIT = "SAFE_EXIT"


class EntityType(str, Enum):
    """Types of entities that can be extracted from scam messages"""
    UPI_ID = "UPI_ID"
    PHONE_NUMBER = "PHONE_NUMBER"
    URL = "URL"
    ORG = "ORG"
    IFSC = "IFSC"
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    BANK_ACCOUNT = "BANK_ACCOUNT"


class Entity(BaseModel):
    """Extracted entity from scam message"""
    type: EntityType
    value: str
    confidence: Optional[float] = Field(default=0.0, ge=0.0, le=1.0)


class AnalysisResult(BaseModel):
    """Main analysis result for scam detection"""
    risk_level: RiskLevel = Field(
        ..., description="Risk level: SAFE, MEDIUM, or HIGH"
    )
    score: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score 0.0 to 1.0"
    )
    classification: str = Field(
        ..., description="Type of scam (e.g., Bank Fraud, Job Offer Scam)"
    )
    reasoning: List[str] = Field(
        ..., description="List of reasons for the classification"
    )
    entities: List[Entity] = Field(
        default_factory=list, description="Extracted entities from message"
    )
    suggested_reply: str = Field(
        ..., description="Safe stalling reply for honey-pot agent"
    )
    agent_state: AgentState = Field(
        ..., description="Current conversation strategy state"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional metadata"
    )


class AnalyzeRequest(BaseModel):
    """Request model for scam analysis endpoint"""
    message: str = Field(
        ..., min_length=1, max_length=10000,
        description="Message to analyze for scam indicators"
    )
    timestamp: Optional[str] = Field(
        default=None, description="Optional timestamp of message"
    )
    session_id: Optional[str] = Field(
        default=None, description="Optional session identifier"
    )

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "message": "Urgent: Your bank account is blocked. Call 9998887776 immediately.",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "session_id": "session-123"
                }
            ]
        }
    }


class ErrorDetails(BaseModel):
    """Error response details"""
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ApiMeta(BaseModel):
    """Response metadata"""
    request_id: str
    timestamp: str
    processing_time_ms: int


class BatchAnalysisResult(BaseModel):
    """Batch analysis result container"""
    results: List[Dict[str, Any]]
    total: int
    successful: int
    failed: int


class ApiResponse(BaseModel):
    """Standard API response wrapper"""
    success: bool
    data: Optional[Union[AnalysisResult, BatchAnalysisResult, Dict[str, Any]]] = None
    error: Optional[ErrorDetails] = None
    meta: Optional[ApiMeta] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "success": True,
                    "data": {
                        "risk_level": "HIGH",
                        "score": 0.95,
                        "classification": "Bank Fraud",
                        "reasoning": ["Urgency tactics", "Request for immediate action"],
                        "entities": [{"type": "PHONE_NUMBER", "value": "9998887776", "confidence": 0.9}],
                        "suggested_reply": "I'm not sure about this. Can you verify?",
                        "agent_state": "DELAY"
                    },
                    "meta": {
                        "request_id": "550e8400-e29b-41d4-a716-446655440000",
                        "timestamp": "2024-01-01T00:00:00Z",
                        "processing_time_ms": 150
                    }
                }
            ]
        }
    }


class HealthCheckResponse(BaseModel):
    """Health check endpoint response"""
    status: str = "healthy"
    version: str
    uptime_seconds: float
    timestamp: str


class ApiInfoResponse(BaseModel):
    """API information endpoint response"""
    name: str
    version: str
    description: str
    endpoints: Dict[str, str]
    authentication: Dict[str, str]
    rate_limit: str

