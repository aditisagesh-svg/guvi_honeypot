"""
Entity Extraction Module
Uses regex patterns and spaCy NER to extract suspicious entities from scam messages
"""

import re
from typing import List, Tuple, Optional
from dataclasses import dataclass
from app.schemas import Entity, EntityType


@dataclass
class ExtractionResult:
    """Result of entity extraction"""
    entities: List[Entity]
    confidence: float


class EntityExtractor:
    """
    Extracts entities from scam messages using:
    - Regex patterns for known formats (phone, email, URL, UPI, etc.)
    - spaCy NER for organization and person names
    """

    def __init__(self):
        """Initialize regex patterns for entity extraction"""
        # Phone numbers (various Indian and international formats)
        self.phone_patterns = [
            r'\b(?:\+?91[-.\s]?)?[6-9]\d{9}\b',  # Indian mobile
            r'\b(?:\+?1[-.\s]?)?[2-9]\d{2}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # US
            r'\b(?:\+?44[-.\s]?)?\d{4}[-.\s]?\d{6}\b',  # UK
            r'\b\d{3}[-.\s]?\d{4}\b',  # Short format
        ]

        # Email addresses
        self.email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        # URLs (including suspicious shorteners)
        self.url_pattern = r'\b(?:https?://)?(?:www\.)?[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}(?:/[^\s]*)?\b'

        # UPI IDs (Indian digital payments)
        self.upi_pattern = r'\b[A-Za-z0-9._-]+@[A-Za-z0-9]+\b'

        # Bank account numbers (basic pattern)
        self.bank_account_pattern = r'\b(?:\d{9,18})\b'

        # IFSC codes (Indian banking)
        self.ifsc_pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'

        # IP addresses
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        # Currency amounts (suspicious payment requests)
        self.currency_pattern = r'[\u20b9\u0024\u20ac]?\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?\s?(?:INR|USD|EUR)?'

        # Initialize spaCy if available
        self._nlp = None
        self._spacy_available = False

    @property
    def nlp(self):
        """Lazy load spaCy model"""
        if self._nlp is None:
            try:
                import spacy
                self._nlp = spacy.load("en_core_web_sm")
                self._spacy_available = True
            except (ImportError, OSError):
                self._nlp = False
        return self._nlp

    def extract_all(self, text: str) -> ExtractionResult:
        """
        Extract all entities from a message

        Args:
            text: The message text to analyze

        Returns:
            ExtractionResult with entities and overall confidence
        """
        entities: List[Entity] = []

        # Extract using regex patterns
        entities.extend(self._extract_phone_numbers(text))
        entities.extend(self._extract_emails(text))
        entities.extend(self._extract_urls(text))
        entities.extend(self._extract_upi_ids(text))
        entities.extend(self._extract_ifsc_codes(text))

        # Extract using spaCy NER
        if self._spacy_available:
            entities.extend(self._extract_spacy_entities(text))

        # Remove duplicates based on type and value
        seen = set()
        unique_entities = []
        for entity in entities:
            key = (entity.type.value, entity.value.lower())
            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)

        # Calculate overall confidence based on extraction method
        confidence = self._calculate_confidence(unique_entities, text)

        return ExtractionResult(entities=unique_entities, confidence=confidence)

    def _extract_phone_numbers(self, text: str) -> List[Entity]:
        """Extract phone numbers using regex patterns"""
        entities = []
        for pattern in self.phone_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                # Validate phone number
                cleaned = re.sub(r'[^\d+]', '', match)
                if len(cleaned) >= 10:
                    entities.append(Entity(
                        type=EntityType.PHONE_NUMBER,
                        value=match,
                        confidence=0.85
                    ))
        return entities

    def _extract_emails(self, text: str) -> List[Entity]:
        """Extract email addresses"""
        entities = []
        matches = re.findall(self.email_pattern, text)
        for match in matches:
            entities.append(Entity(
                type=EntityType.EMAIL,
                value=match,
                confidence=0.9
            ))
        return entities

    def _extract_urls(self, text: str) -> List[Entity]:
        """Extract URLs and domains"""
        entities = []
        matches = re.findall(self.url_pattern, text, re.IGNORECASE)
        for match in matches:
            # Skip if it looks like a regular word
            if '.' in match and not match.startswith('@'):
                # Check for suspicious patterns
                confidence = 0.7
                suspicious_terms = ['bit.ly', 'tinyurl', 'click', 'login', 'verify']
                if any(term in match.lower() for term in suspicious_terms):
                    confidence = 0.85

                entities.append(Entity(
                    type=EntityType.URL,
                    value=match,
                    confidence=confidence
                ))
        return entities

    def _extract_upi_ids(self, text: str) -> List[Entity]:
        """Extract UPI IDs (Indian digital payments)"""
        entities = []
        matches = re.findall(self.upi_pattern, text)
        for match in matches:
            # Filter out email-like patterns that aren't UPI
            if '@' in match:
                entities.append(Entity(
                    type=EntityType.UPI_ID,
                    value=match,
                    confidence=0.85
                ))
        return entities

    def _extract_ifsc_codes(self, text: str) -> List[Entity]:
        """Extract IFSC codes (Indian banking)"""
        entities = []
        matches = re.findall(self.ifsc_pattern, text, re.IGNORECASE)
        for match in matches:
            entities.append(Entity(
                type=EntityType.IFSC,
                value=match.upper(),
                confidence=0.9
            ))
        return entities

    def _extract_spacy_entities(self, text: str) -> List[Entity]:
        """Extract named entities using spaCy"""
        entities = []
        try:
            doc = self.nlp(text)
            for ent in doc.ents:
                entity_type = None
                confidence = 0.75

                if ent.label_ == "ORG":
                    entity_type = EntityType.ORG
                    confidence = 0.8
                elif ent.label_ == "PERSON":
                    entity_type = EntityType.PERSON
                    confidence = 0.8
                elif ent.label_ == "GPE":
                    # Geographic location - could be useful for scams
                    confidence = 0.7

                if entity_type:
                    entities.append(Entity(
                        type=entity_type,
                        value=ent.text,
                        confidence=confidence
                    ))
        except Exception:
            pass  # Fallback if spaCy fails

        return entities

    def _calculate_confidence(self, entities: List[Entity], text: str) -> float:
        """Calculate overall extraction confidence"""
        if not entities:
            return 0.0

        if not text:
            return 0.0

        # Base confidence
        avg_confidence = sum(e.confidence for e in entities) / len(entities)

        # Boost for multiple entity types found
        type_count = len(set(e.type.value for e in entities))
        type_boost = min(type_count * 0.05, 0.2)

        # Boost for suspicious patterns
        suspicious_boost = 0.0
        text_lower = text.lower()

        if any(term in text_lower for term in ['urgent', 'immediately', 'ASAP']):
            suspicious_boost += 0.05
        if any(term in text_lower for term in ['bank', 'account', 'blocked']):
            suspicious_boost += 0.05
        if any(term in text_lower for term in ['payment', 'transfer', 'send']):
            suspicious_boost += 0.05

        return min(avg_confidence + type_boost + suspicious_boost, 1.0)

    def extract_suspicious_indicators(self, text: str) -> List[Tuple[str, int]]:
        """
        Extract suspicious linguistic indicators

        Returns:
            List of (indicator, position) tuples
        """
        indicators = []

        # Urgency patterns
        urgency_patterns = [
            r'urgent(?:ly)?',
            r'immediate(?:ly)?',
            r'ASAP',
            r'right now',
            r'don\'t delay',
            r'time.?limit',
        ]

        # Threat patterns
        threat_patterns = [
            r'blocked',
            r'suspended',
            r'account.?will.?be',
            r'legal.?action',
            r'police',
            r'arrest',
        ]

        # Request patterns
        request_patterns = [
            r'send\s+(?:money|details|information)',
            r'click\s+(?:here|link)',
            r'call\s+\d+',
            r'share\s+(?:OTP|password|PIN)',
            r'verify\s+(?:your|yourself)',
        ]

        text_lower = text.lower()

        for pattern in urgency_patterns:
            for match in re.finditer(pattern, text_lower):
                indicators.append(('urgency', match.start()))

        for pattern in threat_patterns:
            for match in re.finditer(pattern, text_lower):
                indicators.append(('threat', match.start()))

        for pattern in request_patterns:
            for match in re.finditer(pattern, text_lower):
                indicators.append(('request', match.start()))

        return indicators

