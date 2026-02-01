# ScamGuard AI - Python Backend

FastAPI-based backend for the Agentic Honey-Pot Scam Detection system.

## Features

- 🛡️ **ML-Based Detection**: TF-IDF + Logistic Regression for scam classification
- 🔍 **Entity Extraction**: Regex patterns + spaCy NER for phone, email, UPI, URL extraction
- 🤖 **Honey-Pot Agent**: FSM-based conversation strategy (CONFUSE/DELAY/EXTRACT)
- 📡 **RESTful API**: Production-ready FastAPI endpoints with authentication
- ✅ **Type Safety**: Pydantic models for request/response validation

## Project Structure

```
backend/
├── app/
│   ├── __init__.py         # Package initialization
│   ├── main.py             # FastAPI entry point
│   ├── model.py            # TF-IDF + Logistic Regression model
│   ├── detector.py         # Scam detection logic
│   ├── entities.py         # Entity extraction (regex + spaCy)
│   ├── agent.py            # Honey-pot agent FSM
│   └── schemas.py          # Pydantic models
├── tests/
│   └── test_api.py         # Unit tests
├── models/                 # Saved model files
├── requirements.txt        # Python dependencies
├── .env.example           # Environment configuration template
└── README.md              # This file
```

## Quick Start

### 1. Create Virtual Environment

```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt

# Download spaCy model (required for entity extraction)
python -m spacy download en_core_web_sm
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 4. Run the Server

```bash
# Development mode
python -m app.main

# Or with uvicorn directly
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 5. Access API Documentation

Once running, open:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## API Endpoints

### POST /api/v1/analyze

Analyze a message for scam indicators.

**Request:**
```json
{
  "message": "Urgent: Your bank account is blocked. Call 9998887776...",
  "timestamp": "2024-01-01T00:00:00Z",
  "session_id": "session-123"
}
```

**Response:**
```json
{
  "success": true,
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
```

### POST /api/v1/analyze/batch

Analyze multiple messages (max 10).

### GET /api/v1/health

Health check endpoint.

### GET /api/v1

API information.

### POST /api/v1/agent/respond

Generate honey-pot response for conversation.

### GET /api/v1/agent/intelligence/{session_id}

Get extracted intelligence for a session.

## Authentication

Provide API key in header:
```
X-API-KEY: your-api-key
```
Or as Bearer token:
```
Authorization: Bearer your-api-key
```

Set `API_KEY` in `.env` for production. Leave empty for development mode.

## Risk Levels

| Level | Description |
|-------|-------------|
| `SAFE` | Score < 0.4 - Likely legitimate message |
| `MEDIUM` | Score 0.4-0.7 - Potential scam indicators |
| `HIGH` | Score >= 0.7 - Strong scam indicators |

## Agent States

| State | Description |
|-------|-------------|
| `CONFUSE` | Respond with confusing/non-sequitur messages |
| `DELAY` | Stall with excuses to waste scammer time |
| `EXTRACT` | Actively gather intelligence about scammer |
| `SAFE_EXIT` | Safely end conversation |

## Running Tests

```bash
pytest backend/tests/ -v
```

## Deployment

### Using Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy model
RUN python -m spacy download en_core_web_sm

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Server host | `0.0.0.0` |
| `PORT` | Server port | `8000` |
| `DEBUG` | Debug mode | `false` |
| `API_KEY` | API authentication key | (empty) |
| `CORS_ORIGIN` | Allowed CORS origins | `*` |

## Performance

- **Latency**: < 200ms for single message analysis
- **Throughput**: Supports 100+ requests/minute
- **Model**: Pre-trained with 100+ scam patterns

## License

MIT License

