"""
ScamGuard AI - FastAPI Main Entry Point
Agentic Honey-Pot Scam Detection API

This module provides a production-ready API for scam message analysis
with ML-based detection, entity extraction, and honey-pot conversation strategy.
"""

import os
import sys
import time
import uuid
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.schemas import (
    AnalyzeRequest,
    ApiResponse,
    HealthCheckResponse,
    ApiInfoResponse,
    RiskLevel,
    AgentState,
)
from app.detector import ScamDetector
from app.agent import HoneyPotAgent


# Initialize services (lazy loading for better startup performance)
_detector: ScamDetector = None
_agent: HoneyPotAgent = None


def get_detector() -> ScamDetector:
    """Get or create detector instance"""
    global _detector
    if _detector is None:
        _detector = ScamDetector()
    return _detector


def get_agent() -> HoneyPotAgent:
    """Get or create agent instance"""
    global _agent
    if _agent is None:
        _agent = HoneyPotAgent()
    return _agent


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    print("Starting ScamGuard AI Backend...")
    _ = get_detector()  # Initialize detector
    _ = get_agent()     # Initialize agent
    print("ScamGuard AI Backend started successfully")
    yield
    # Shutdown
    print("Shutting down ScamGuard AI Backend...")


# Create FastAPI application
app = FastAPI(
    title="ScamGuard AI - Agentic Honey-Pot API",
    description="""
    🛡️ ScamGuard AI - Agentic Honey-Pot Scam Detection API

    This API analyzes scam messages and returns extracted intelligence
    including risk assessment, entities, and honey-pot conversation strategies.

    ## Features
    - ML-based scam detection (TF-IDF + Logistic Regression)
    - Entity extraction (phone, email, UPI, URL, etc.)
    - Finite State Machine for honey-pot strategy
    - Production-ready with API key authentication

    ## Authentication
    Provide API key in `X-API-KEY` header or `Authorization: Bearer <key>` header.
    """,
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ============================================================================
# CORS CONFIGURATION
# ============================================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-KEY", "X-Request-ID"],
)


# ============================================================================
# CONFIGURATION
# ============================================================================

API_KEY = os.getenv("API_KEY", "")
API_KEY_HEADER = "x-api-key"
BEARER_PREFIX = "Bearer "


# ============================================================================
# AUTHENTICATION DEPENDENCY
# ============================================================================

async def verify_api_key(
    x_api_key: str = Header(None, alias=API_KEY_HEADER),
    authorization: str = Header(None),
) -> str:
    """
    Verify API key from request headers

    Args:
        x_api_key: API key from X-API-KEY header
        authorization: Authorization header value

    Returns:
        Validated API key

    Raises:
        HTTPException: If API key is missing or invalid
    """
    # Development mode: allow access if no API key is set
    if not API_KEY:
        return "dev-key"

    # Check X-API-KEY header
    provided_key = x_api_key

    # Check Authorization header (Bearer token)
    if not provided_key and authorization:
        if authorization.startswith(BEARER_PREFIX):
            provided_key = authorization[len(BEARER_PREFIX):]

    if not provided_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": {
                    "code": "UNAUTHORIZED",
                    "message": "API key is required. Provide it in X-API-KEY header or Authorization: Bearer <key>",
                }
            },
        )

    if provided_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "FORBIDDEN",
                    "message": "Invalid API key provided",
                }
            },
        )

    return provided_key


# ============================================================================
# REQUEST ID MIDDLEWARE
# ============================================================================

@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add unique request ID to each request"""
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.detail,
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """General exception handler for unhandled errors"""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "success": False,
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "details": str(exc) if os.getenv("DEBUG") else None,
            },
            "meta": {
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "processing_time_ms": 0,
            },
        },
    )


# ============================================================================
# HEALTH CHECK ENDPOINTS
# ============================================================================

@app.get("/", response_model=HealthCheckResponse, tags=["Health"])
async def root():
    """Root endpoint - basic health check"""
    return HealthCheckResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=time.time(),
        timestamp=datetime.utcnow().isoformat() + "Z",
    )


@app.get("/health", response_model=HealthCheckResponse, tags=["Health"])
async def health_check():
    """Detailed health check endpoint"""
    return HealthCheckResponse(
        status="healthy",
        version="1.0.0",
        uptime_seconds=time.time(),
        timestamp=datetime.utcnow().isoformat() + "Z",
    )


@app.get("/api/v1", response_model=ApiInfoResponse, tags=["API"])
async def api_info():
    """API information endpoint"""
    return ApiInfoResponse(
        name="ScamGuard AI - Agentic Honey-Pot API",
        version="1.0.0",
        description="API for scam message analysis and intelligence extraction",
        endpoints={
            "POST /api/v1/analyze": "Analyze a message for scam indicators",
            "POST /api/v1/analyze/batch": "Batch analyze multiple messages (max 10)",
            "GET /api/v1/health": "Health check endpoint",
            "GET /api/v1": "API information",
        },
        authentication={
            "type": "API Key",
            "header": "X-API-KEY",
            "alternative": "Authorization: Bearer <api-key>",
        },
        rate_limit="100 requests per minute",
    )


# ============================================================================
# MAIN ANALYSIS ENDPOINT
# ============================================================================

@app.post(
    "/api/v1/analyze",
    response_model=ApiResponse,
    tags=["Analysis"],
    summary="Analyze message for scam indicators",
    description="""
    Analyzes a message for potential scam activity and returns:
    - Risk level (SAFE/MEDIUM/HIGH)
    - Confidence score (0.0 to 1.0)
    - Classification type (e.g., Bank Fraud, Job Offer Scam)
    - Reasoning for the analysis
    - Extracted entities (phone, email, UPI, URL, etc.)
    - Suggested reply for honey-pot interaction
    - Agent state for conversation strategy
    """,
)
async def analyze_message(
    body: AnalyzeRequest,
    x_api_key: str = Depends(verify_api_key),
    fastapi_request: Request = None,
) -> ApiResponse:
    """
    Analyze a single message for scam indicators.

    Request body:
    ```json
    {
        "message": "Urgent: Your bank account is blocked. Call 9998887776...",
        "timestamp": "2024-01-01T00:00:00Z",  // optional
        "session_id": "session-123"  // optional
    }
    ```

    Response:
    ```json
    {
        "success": true,
        "data": {
            "risk_level": "HIGH",
            "score": 0.95,
            "classification": "Bank Fraud",
            "reasoning": ["Urgency tactics", "Request for immediate action"],
            "entities": [{"type": "PHONE_NUMBER", "value": "9998887776"}],
            "suggested_reply": "I'm not sure about this. Can you verify?",
            "agent_state": "DELAY"
        },
        "meta": {
            "request_id": "uuid-v4",
            "timestamp": "2024-01-01T00:00:00Z",
            "processing_time_ms": 150
        }
    }
    ```
    """
    start_time = time.time()
    request_id = getattr(fastapi_request.state, "request_id", str(uuid.uuid4()))

    try:
        # Get detector instance
        detector = get_detector()

        # Analyze the message
        detection = detector.analyze(body.message)

        # Convert to response format
        result = detector.to_analysis_result(detection)

        # Calculate processing time
        processing_time_ms = int((time.time() - start_time) * 1000)

        # Log the analysis
        print(
            f"[{request_id}] Analyzed message. "
            f"Risk: {result.risk_level.value}, "
            f"Score: {result.score:.2f}, "
            f"Time: {processing_time_ms}ms"
        )

        return ApiResponse(
            success=True,
            data=result,
            meta={
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "processing_time_ms": processing_time_ms,
            },
        )

    except Exception as exc:
        processing_time_ms = int((time.time() - start_time) * 1000)
        print(f"[{request_id}] Error analyzing message: {exc}")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Failed to analyze message",
                    "details": str(exc) if os.getenv("DEBUG") else None,
                },
                "meta": {
                    "request_id": request_id,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "processing_time_ms": processing_time_ms,
                },
            },
        )


# ============================================================================
# BATCH ANALYSIS ENDPOINT
# ============================================================================

@app.post(
    "/api/v1/analyze/batch",
    response_model=ApiResponse,
    tags=["Analysis"],
    summary="Analyze multiple messages",
    description="Analyze up to 10 messages in a single request",
)
async def analyze_batch(
    request: Request,
    api_key: str = Depends(verify_api_key),
) -> ApiResponse:
    """
    Analyze multiple messages in a single request.

    Request body:
    ```json
    {
        "messages": [
            {"message": "Message 1...", "session_id": "session-1"},
            {"message": "Message 2...", "session_id": "session-2"}
        ]
    }
    ```

    Max 10 messages per batch.
    """
    start_time = time.time()
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

    try:
        body = await request.json()

        if "messages" not in body:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "messages field is required",
                    },
                    "meta": {
                        "request_id": request_id,
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "processing_time_ms": 0,
                    },
                },
            )

        messages = body["messages"]

        if not isinstance(messages, list):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "messages must be an array",
                    },
                    "meta": {
                        "request_id": request_id,
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "processing_time_ms": 0,
                    },
                },
            )

        if len(messages) > 10:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "success": False,
                    "error": {
                        "code": "VALIDATION_ERROR",
                        "message": "Maximum 10 messages per batch request",
                        "details": {"maxBatchSize": 10, "requestedSize": len(messages)},
                    },
                    "meta": {
                        "request_id": request_id,
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "processing_time_ms": 0,
                    },
                },
            )

        # Get detector instance
        detector = get_detector()

        # Analyze all messages
        results = []
        for idx, msg in enumerate(messages):
            try:
                message_text = msg.get("message", "")
                detection = detector.analyze(message_text)
                result = detector.to_analysis_result(detection)
                results.append({
                    "index": idx,
                    "success": True,
                    "result": result.model_dump(),
                })
            except Exception as exc:
                results.append({
                    "index": idx,
                    "success": False,
                    "error": str(exc),
                })

        processing_time_ms = int((time.time() - start_time) * 1000)

        successful = sum(1 for r in results if r["success"])
        failed = len(results) - successful

        return ApiResponse(
            success=True,
            data={
                "results": results,
                "total": len(results),
                "successful": successful,
                "failed": failed,
            },
            meta={
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "processing_time_ms": processing_time_ms,
            },
        )

    except HTTPException:
        raise
    except Exception as exc:
        processing_time_ms = int((time.time() - start_time) * 1000)
        print(f"[{request_id}] Error in batch analysis: {exc}")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Failed to process batch request",
                },
                "meta": {
                    "request_id": request_id,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "processing_time_ms": processing_time_ms,
                },
            },
        )


# ============================================================================
# HONEY-POT ENDPOINTS
# ============================================================================

@app.post(
    "/api/v1/agent/respond",
    response_model=ApiResponse,
    tags=["Honey-Pot"],
    summary="Generate honey-pot response",
    description="Generate an appropriate honey-pot response based on current state",
)
async def generate_response(
    session_id: str,
    current_message: str,
    risk_level: str,
    api_key: str = Depends(verify_api_key),
) -> ApiResponse:
    """
    Generate a honey-pot response based on conversation state.

    Request body:
    ```json
    {
        "session_id": "session-123",
        "current_message": "Scammer's message...",
        "risk_level": "HIGH"
    }
    ```
    """
    start_time = time.time()
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

    try:
        agent = get_agent()

        # Parse risk level
        try:
            risk = RiskLevel(risk_level.upper())
        except ValueError:
            risk = RiskLevel.SAFE

        # Get or create session
        context = agent.get_context(session_id)

        # Add message to context
        context.messages.append({
            "role": "scammer",
            "content": current_message,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })

        # Generate response based on state
        response_text = agent.get_response(context)

        processing_time_ms = int((time.time() - start_time) * 1000)

        return ApiResponse(
            success=True,
            data={
                "response": response_text,
                "agent_state": context.state.value,
                "session_id": session_id,
            },
            meta={
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "processing_time_ms": processing_time_ms,
            },
        )

    except Exception as exc:
        processing_time_ms = int((time.time() - start_time) * 1000)
        print(f"[{request_id}] Error generating response: {exc}")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Failed to generate response",
                },
                "meta": {
                    "request_id": request_id,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "processing_time_ms": processing_time_ms,
                },
            },
        )


@app.get(
    "/api/v1/agent/intelligence/{session_id}",
    response_model=ApiResponse,
    tags=["Honey-Pot"],
    summary="Get extracted intelligence",
    description="Get intelligence extracted from a honey-pot conversation session",
)
async def get_intelligence(
    session_id: str,
    api_key: str = Depends(verify_api_key),
) -> ApiResponse:
    """Get extracted intelligence for a session"""
    start_time = time.time()
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

    try:
        agent = get_agent()
        intelligence = agent.get_intelligence_summary(session_id)

        processing_time_ms = int((time.time() - start_time) * 1000)

        return ApiResponse(
            success=True,
            data=intelligence,
            meta={
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "processing_time_ms": processing_time_ms,
            },
        )

    except Exception as exc:
        processing_time_ms = int((time.time() - start_time) * 1000)
        print(f"[{request_id}] Error getting intelligence: {exc}")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "success": False,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "Failed to get intelligence",
                },
                "meta": {
                    "request_id": request_id,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "processing_time_ms": processing_time_ms,
                },
            },
        )


# ============================================================================
# 404 HANDLER
# ============================================================================

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Custom 404 handler"""
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "success": False,
            "error": {
                "code": "NOT_FOUND",
                "message": f"Route {request.method} {request.url.path} not found",
            },
            "meta": {
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "processing_time_ms": 0,
            },
        },
    )


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "false").lower() == "true"

    print(f"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🛡️  ScamGuard AI - Agentic Honey-Pot API                   ║
║   =========================================                   ║
║                                                               ║
║   Server running on: http://{host}:{port}                       ║
║   API Base URL:      http://{host}:{port}/api/v1                ║
║   Health Check:      http://{host}:{port}/health                 ║
║   API Docs:          http://{host}:{port}/docs                  ║
║                                                               ║
║   Endpoints:                                                   ║
║   - POST /api/v1/analyze     Analyze scam messages            ║
║   - POST /api/v1/analyze/batch  Batch analysis (max 10)       ║
║   - POST /api/v1/agent/respond  Honey-pot response            ║
║   - GET  /api/v1/agent/intelligence/{session_id}  Get intel       ║
║   - GET  /api/v1/health      Health check                     ║
║   - GET  /api/v1             API information                  ║
║                                                               ║
║   Authentication:                                             ║
║   Header: X-API-KEY: <your-api-key>                           ║
║   Or: Authorization: Bearer <your-api-key>                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """.strip())

    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info" if not debug else "debug",
    )

