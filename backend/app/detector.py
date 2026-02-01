"""
Scam Detection Module
Main prediction logic combining ML model and entity extraction
"""

import re
from typing import List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime

from app.model import ScamDetectionModel
from app.entities import EntityExtractor
from app.schemas import (
    AnalysisResult, Entity, RiskLevel, AgentState,
    EntityType
)


@dataclass
class DetectionResult:
    """Complete detection result"""
    risk_level: RiskLevel
    score: float
    classification: str
    reasoning: List[str]
    entities: List[Entity]
    suggested_reply: str
    agent_state: AgentState


class ScamDetector:
    """
    Main scam detection service combining:
    - ML-based text classification (TF-IDF + Logistic Regression)
    - Entity extraction (Regex + spaCy NER)
    - Risk scoring and classification
    - Honey-pot response generation
    """

    def __init__(self):
        """Initialize detector with ML model and entity extractor"""
        self.model = ScamDetectionModel()
        self.extractor = EntityExtractor()

    def analyze(self, message: str) -> DetectionResult:
        """
        Analyze a message for scam indicators

        Args:
            message: The message text to analyze

        Returns:
            DetectionResult with all analysis details
        """
        # Extract entities
        extraction = self.extractor.extract_all(message)

        # Get ML classification details
        ml_details = self.model.get_classification_details(message)

        # Get suspicious linguistic indicators
        indicators = self.extractor.extract_suspicious_indicators(message)

        # Calculate risk score
        risk_score = self._calculate_risk_score(
            ml_details,
            extraction,
            indicators
        )

        # Determine risk level
        risk_level = self._determine_risk_level(risk_score)

        # Generate reasoning
        reasoning = self._generate_reasoning(ml_details, extraction, indicators)

        # Determine agent state
        agent_state = self._determine_agent_state(risk_level, ml_details)

        # Generate suggested reply
        suggested_reply = self._generate_response(risk_level, agent_state)

        # Determine classification
        classification = ml_details.get('scam_type', 'General Scam')

        # Convert entities to schema format
        entities = extraction.entities

        return DetectionResult(
            risk_level=risk_level,
            score=risk_score,
            classification=classification,
            reasoning=reasoning,
            entities=entities,
            suggested_reply=suggested_reply,
            agent_state=agent_state
        )

    def _calculate_risk_score(
        self,
        ml_details: dict,
        extraction: 'ExtractionResult',
        indicators: List[Tuple[str, int]]
    ) -> float:
        """
        Calculate comprehensive risk score

        Args:
            ml_details: ML model classification details
            extraction: Entity extraction results
            indicators: List of (type, position) tuples

        Returns:
            Risk score between 0.0 and 1.0
        """
        score = 0.0

        # ML model contribution (0.0 - 0.5)
        ml_score = ml_details.get('scam_probability', 0.0)
        score += ml_score * 0.5

        # Entity extraction contribution (0.0 - 0.25)
        entity_count = len(extraction.entities)
        entity_risk = min(entity_count * 0.05, 0.25)
        score += entity_risk

        # Urgency/threat indicators (0.0 - 0.15)
        urgency_count = sum(1 for i_type, _ in indicators if i_type == 'urgency')
        threat_count = sum(1 for i_type, _ in indicators if i_type == 'threat')
        request_count = sum(1 for i_type, _ in indicators if i_type == 'request')

        indicator_risk = min((urgency_count + threat_count) * 0.05, 0.10)
        request_risk = min(request_count * 0.05, 0.05)
        score += indicator_risk + request_risk

        # High-risk entity boost
        high_risk_entities = [
            EntityType.PHONE_NUMBER,
            EntityType.UPI_ID,
            EntityType.BANK_ACCOUNT,
            EntityType.URL
        ]
        has_high_risk = any(
            e.type in high_risk_entities for e in extraction.entities
        )
        if has_high_risk:
            score += 0.10

        # Normalize to 0-1 range
        return min(score, 1.0)

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        if score >= 0.7:
            return RiskLevel.HIGH
        elif score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.SAFE

    def _generate_reasoning(
        self,
        ml_details: dict,
        extraction: 'ExtractionResult',
        indicators: List[Tuple[str, int]]
    ) -> List[str]:
        """Generate human-readable reasoning for the analysis"""
        reasoning = []

        # Add ML-based reasoning
        indicators_found = ml_details.get('indicators', [])
        for indicator in indicators_found:
            if indicator.startswith('urgency'):
                reasoning.append("Urgency tactics detected")
            elif indicator.startswith('threat'):
                reasoning.append("Threatening language used")
            elif indicator.startswith('request'):
                reasoning.append("Suspicious request for information/money")
            elif indicator.startswith('reward'):
                reasoning.append("Too-good-to-be-true reward claim")

        # Add entity-based reasoning
        entity_types = set(e.type for e in extraction.entities)
        if EntityType.PHONE_NUMBER in entity_types:
            reasoning.append("Phone number extracted - potential contact for scam")
        if EntityType.URL in entity_types:
            reasoning.append("URL extracted - possible phishing link")
        if EntityType.UPI_ID in entity_types:
            reasoning.append("UPI payment ID extracted - payment request detected")
        if EntityType.EMAIL in entity_types:
            reasoning.append("Email address extracted - contact method identified")
        if EntityType.BANK_ACCOUNT in entity_types:
            reasoning.append("Bank account number extracted - financial data request")

        # Add classification reasoning
        scam_type = ml_details.get('scam_type', '')
        if scam_type and scam_type != 'Not Scam':
            reasoning.append(f"Pattern matches: {scam_type}")

        # Add confidence reasoning
        confidence = ml_details.get('confidence', 0)
        if confidence >= 0.8:
            reasoning.append("High confidence classification")
        elif confidence >= 0.6:
            reasoning.append("Moderate confidence classification")

        # Default reasoning if none found
        if not reasoning:
            if ml_details.get('scam_probability', 0) > 0.5:
                reasoning.append("Text analysis indicates potential scam")
            else:
                reasoning.append("No strong scam indicators detected")

        return reasoning

    def _determine_agent_state(
        self,
        risk_level: RiskLevel,
        ml_details: dict
    ) -> AgentState:
        """Determine honey-pot agent state based on analysis"""
        # High risk: Extract more intelligence
        if risk_level == RiskLevel.HIGH:
            return AgentState.EXTRACT

        # Medium risk: Delay and gather more info
        if risk_level == RiskLevel.MEDIUM:
            return AgentState.DELAY

        # Low risk: Can confuse the scammer
        if risk_level == RiskLevel.SAFE:
            return AgentState.CONFUSE

        return AgentState.DELAY

    def _generate_response(
        self,
        risk_level: RiskLevel,
        agent_state: AgentState
    ) -> str:
        """Generate appropriate honey-pot response"""
        responses = {
            (RiskLevel.SAFE, AgentState.CONFUSE): [
                "I'm not sure I understand. Can you explain more about what you need?",
                "That sounds interesting! Tell me more details.",
                "Could you clarify what you mean by that?",
                "I'm a bit confused. Can you walk me through this step by step?",
                "Thanks for reaching out! Let me think about this.",
            ],
            (RiskLevel.SAFE, AgentState.DELAY): [
                "Let me check my schedule and get back to you.",
                "I need to verify some information first. Can you wait?",
                "This sounds important. Let me make sure I understand correctly.",
                "I'll need to discuss this with my family first.",
                "Give me some time to think about this opportunity.",
            ],
            (RiskLevel.MEDIUM, AgentState.DELAY): [
                "I'm interested but need more information first.",
                "This sounds urgent but I want to make sure it's legitimate.",
                "Can you provide more details about your organization?",
                "I need to verify this with my bank first.",
                "Let me check if this is something I can help with.",
            ],
            (RiskLevel.MEDIUM, AgentState.EXTRACT): [
                "I'd love to help! What's your name and where are you calling from?",
                "That sounds concerning. Can you tell me more about yourself?",
                "I'm worried about my account. How can I reach you directly?",
                "This is confusing. Can you explain the process again?",
                "I want to make sure I do this right. What exactly do I need to do?",
            ],
            (RiskLevel.HIGH, AgentState.EXTRACT): [
                "I'm very concerned. Can you give me your phone number so I can call you back?",
                "I need to act fast. What's your full name and company details?",
                "This is scaring me a bit. Can you reassure me this is legitimate?",
                "I want to help but need to be sure. What's your office address?",
                "I'm not good with technology. Can you walk me through this slowly?",
            ],
        }

        import random
        response_key = (risk_level, agent_state)
        available_responses = responses.get(response_key, responses[(RiskLevel.MEDIUM, AgentState.DELAY)])
        return random.choice(available_responses)

    def to_analysis_result(self, detection: DetectionResult) -> AnalysisResult:
        """Convert DetectionResult to API schema format"""
        return AnalysisResult(
            risk_level=detection.risk_level,
            score=detection.score,
            classification=detection.classification,
            reasoning=detection.reasoning,
            entities=detection.entities,
            suggested_reply=detection.suggested_reply,
            agent_state=detection.agent_state,
            metadata={
                "model": "tfidf-logistic-regression",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
        )

