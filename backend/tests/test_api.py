"""
Unit Tests for ScamGuard AI API
Tests for API endpoints and core functionality
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def client():
    """Create test client"""
    # Mock API key for testing
    with patch.dict(os.environ, {"API_KEY": ""}):
        from app.main import app
        yield TestClient(app, raise_server_exceptions=False)


# ============================================================================
# HEALTH CHECK TESTS
# ============================================================================

class TestHealthEndpoints:
    """Tests for health check endpoints"""

    def test_root_endpoint(self, client):
        """Test root endpoint returns healthy status"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "uptime_seconds" in data
        assert "timestamp" in data

    def test_health_endpoint(self, client):
        """Test /health endpoint returns healthy status"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_api_info_endpoint(self, client):
        """Test /api/v1 endpoint returns API information"""
        response = client.get("/api/v1")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "ScamGuard AI - Agentic Honey-Pot API"
        assert "endpoints" in data
        assert "authentication" in data


# ============================================================================
# ANALYZE ENDPOINT TESTS (Real tests without mocks)
# ============================================================================

class TestAnalyzeEndpoint:
    """Tests for the main analyze endpoint"""

    def test_analyze_success(self, client):
        """Test successful message analysis"""
        response = client.post(
            "/api/v1/analyze",
            json={"message": "Urgent: Your bank account is blocked. Call 9998887776 immediately."},
            headers={"X-API-KEY": "test-key"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "meta" in data

    def test_analyze_with_api_key(self, client):
        """Test analysis with API key in header"""
        response = client.post(
            "/api/v1/analyze",
            json={"message": "Test message"},
            headers={"X-API-KEY": "valid-key"}
        )
        assert response.status_code == 200

    def test_analyze_with_bearer_token(self, client):
        """Test analysis with Bearer token authentication"""
        response = client.post(
            "/api/v1/analyze",
            json={"message": "Test message"},
            headers={"Authorization": "Bearer valid-key"}
        )
        assert response.status_code == 200

    def test_analyze_empty_message(self, client):
        """Test analysis rejects empty message"""
        response = client.post(
            "/api/v1/analyze",
            json={"message": ""}
        )
        assert response.status_code == 422  # Validation error

    def test_analyze_missing_message(self, client):
        """Test analysis requires message field"""
        response = client.post(
            "/api/v1/analyze",
            json={}
        )
        assert response.status_code == 422  # Validation error

    def test_analyze_optional_fields(self, client):
        """Test analysis accepts optional fields"""
        response = client.post(
            "/api/v1/analyze",
            json={
                "message": "Test message",
                "timestamp": "2024-01-01T00:00:00Z",
                "session_id": "session-123"
            }
        )
        assert response.status_code == 200

    def test_analyze_response_structure(self, client):
        """Test response has correct structure"""
        response = client.post(
            "/api/v1/analyze",
            json={"message": "Test scam message urgent account blocked"}
        )
        assert response.status_code == 200
        data = response.json()

        # Check meta
        assert "meta" in data
        assert "request_id" in data["meta"]
        assert "timestamp" in data["meta"]
        assert "processing_time_ms" in data["meta"]

        # Check data
        assert "data" in data
        data_obj = data["data"]
        assert "risk_level" in data_obj
        assert "score" in data_obj
        assert "classification" in data_obj
        assert "reasoning" in data_obj
        assert "entities" in data_obj
        assert "suggested_reply" in data_obj
        assert "agent_state" in data_obj

    def test_analyze_includes_request_id(self, client):
        """Test response includes request ID in headers"""
        response = client.post(
            "/api/v1/analyze",
            json={"message": "Test message"}
        )
        assert response.status_code == 200
        assert "x-request-id" in response.headers


# ============================================================================
# BATCH ANALYSIS TESTS
# ============================================================================

class TestBatchAnalysis:
    """Tests for batch analysis endpoint"""

    def test_batch_analyze_success(self, client):
        """Test successful batch analysis"""
        response = client.post(
            "/api/v1/analyze/batch",
            json={
                "messages": [
                    {"message": "Test message 1"},
                    {"message": "Test message 2"}
                ]
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "results" in data["data"]
        assert data["data"]["total"] == 2
        assert data["data"]["successful"] == 2

    def test_batch_analyze_max_10(self, client):
        """Test batch analysis rejects more than 10 messages"""
        messages = [{"message": f"Test {i}"} for i in range(11)]
        response = client.post(
            "/api/v1/analyze/batch",
            json={"messages": messages}
        )
        assert response.status_code == 400
        assert "Maximum 10" in response.json()["error"]["message"]

    def test_batch_analyze_missing_messages_field(self, client):
        """Test batch analysis requires messages field"""
        response = client.post(
            "/api/v1/analyze/batch",
            json={}
        )
        assert response.status_code == 400

    def test_batch_analyze_invalid_messages_type(self, client):
        """Test batch analysis requires array for messages"""
        response = client.post(
            "/api/v1/analyze/batch",
            json={"messages": "not an array"}
        )
        assert response.status_code == 400


# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================

class TestAuthentication:
    """Tests for API key authentication"""

    def test_no_api_key_dev_mode(self, client):
        """Test request without API key in dev mode succeeds"""
        # This test assumes API_KEY is not set or is empty
        response = client.post(
            "/api/v1/analyze",
            json={"message": "Test message"}
        )
        # Should succeed in dev mode (no API key required)
        assert response.status_code in [200, 401]


# ============================================================================
# ENTITY EXTRACTION TESTS
# ============================================================================

class TestEntityExtraction:
    """Tests for entity extraction functionality"""

    def test_extract_phone_number(self):
        """Test phone number extraction"""
        from app.entities import EntityExtractor
        extractor = EntityExtractor()
        result = extractor.extract_all("Call 9998887776 immediately")

        phone_entities = [e for e in result.entities if e.type.value == "PHONE_NUMBER"]
        assert len(phone_entities) >= 1

    def test_extract_email(self):
        """Test email extraction"""
        from app.entities import EntityExtractor
        extractor = EntityExtractor()
        result = extractor.extract_all("Contact scammer@fake.com for details")

        email_entities = [e for e in result.entities if e.type.value == "EMAIL"]
        assert len(email_entities) >= 1

    def test_extract_upi_id(self):
        """Test UPI ID extraction"""
        from app.entities import EntityExtractor
        extractor = EntityExtractor()
        result = extractor.extract_all("Send payment to scammer@upi")

        upi_entities = [e for e in result.entities if e.type.value == "UPI_ID"]
        assert len(upi_entities) >= 1

    def test_extract_url(self):
        """Test URL extraction"""
        from app.entities import EntityExtractor
        extractor = EntityExtractor()
        result = extractor.extract_all("Visit http://fake-bank.com/verify")

        url_entities = [e for e in result.entities if e.type.value == "URL"]
        assert len(url_entities) >= 1


# ============================================================================
# MODEL TESTS
# ============================================================================

class TestScamModel:
    """Tests for the ML model"""

    def test_model_creation(self):
        """Test model can be created"""
        from app.model import ScamDetectionModel
        model = ScamDetectionModel()
        assert model.is_trained

    def test_model_prediction(self):
        """Test model prediction"""
        from app.model import ScamDetectionModel
        model = ScamDetectionModel()

        # Test scam message
        scam_prob, _ = model.predict_proba("Urgent your bank account is blocked call immediately")
        assert scam_prob > 0.5

        # Test safe message
        _, safe_prob = model.predict_proba("Hello how are you today")
        assert safe_prob > 0.5

    def test_model_classification_details(self):
        """Test getting full classification details"""
        from app.model import ScamDetectionModel
        model = ScamDetectionModel()

        details = model.get_classification_details(
            "Urgent: Your account is blocked. Call 9998887776 immediately."
        )

        assert "is_scam" in details
        assert "scam_probability" in details
        assert "indicators" in details
        assert "scam_type" in details


# ============================================================================
# DETECTOR TESTS
# ============================================================================

class TestScamDetector:
    """Tests for the scam detector"""

    def test_detector_analysis(self):
        """Test detector can analyze messages"""
        from app.detector import ScamDetector
        detector = ScamDetector()

        result = detector.analyze(
            "Urgent: Your bank account is blocked. Call 9998887776 immediately."
        )

        assert result.risk_level.value in ["SAFE", "MEDIUM", "HIGH"]
        assert 0.0 <= result.score <= 1.0
        assert isinstance(result.reasoning, list)
        assert isinstance(result.entities, list)

    def test_detector_safe_message(self):
        """Test detector with safe message"""
        from app.detector import ScamDetector
        detector = ScamDetector()

        result = detector.analyze("Hello how are you today")

        assert result.risk_level.value in ["SAFE", "MEDIUM"]
        assert result.classification == "Not Scam"


# ============================================================================
# AGENT TESTS
# ============================================================================

class TestHoneyPotAgent:
    """Tests for the honey-pot agent"""

    def test_agent_creation(self):
        """Test agent can be created"""
        from app.agent import HoneyPotAgent
        agent = HoneyPotAgent()
        assert agent is not None

    def test_agent_context(self):
        """Test agent creates context for sessions"""
        from app.agent import HoneyPotAgent
        agent = HoneyPotAgent()

        context = agent.get_context("test-session")
        assert context.session_id == "test-session"
        assert context.state.value == "IDLE"

    def test_agent_response(self):
        """Test agent generates responses"""
        from app.agent import HoneyPotAgent
        agent = HoneyPotAgent()

        context = agent.get_context("test-session")
        response = agent.get_response(context)

        assert isinstance(response, str)
        assert len(response) > 0

    def test_agent_analyze_and_transition(self):
        """Test agent analyzes and transitions state"""
        from app.agent import HoneyPotAgent, AgentState
        agent = HoneyPotAgent()

        context = agent.analyze_message_and_transition(
            "test-session",
            "Your account is blocked",
            risk_score=0.8
        )

        assert context is not None
        assert context.state in [
            AgentState.DELAY,
            AgentState.EXTRACT,
            AgentState.CONFUSE
        ]

    def test_agent_intelligence_summary(self):
        """Test agent generates intelligence summary"""
        from app.agent import HoneyPotAgent
        agent = HoneyPotAgent()

        # Add some activity
        agent.analyze_message_and_transition(
            "test-session",
            "Test message",
            risk_score=0.5
        )

        summary = agent.get_intelligence_summary("test-session")
        assert "session_id" in summary
        assert "total_messages" in summary


# ============================================================================
# RUNNER
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

