# 🛡️ ScamGuard AI - Agentic Honey-Pot API

A production-ready API for scam message analysis and intelligence extraction, built with Node.js, Express, and Google's Gemini AI.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [API Documentation](#api-documentation)
- [Configuration](#configuration)
- [Testing the Endpoint](#testing-the-endpoint)
- [Expected Results](#expected-results)
- [Evaluation Readiness Checklist](#evaluation-readiness-checklist)
- [Deployment](#deployment)

---

## 🎯 Overview

This API serves as an **Agentic Honey-Pot** backend that:
- Accepts scam messages via REST API
- Analyzes messages using Google's Gemini 3 Flash AI
- Extracts intelligence (entities, classification, risk level)
- Generates safe stalling replies for honey-pot engagement
- Returns structured JSON responses for automated evaluation

**Problem Statement Alignment:** This directly addresses Problem 2 (Agentic Honey-Pot) by providing a live API endpoint that accepts scam messages and returns extracted intelligence.

---

## ✨ Features

- 🔍 **Intelligent Analysis**: Uses Gemini AI to detect and classify scam messages
- 🏷️ **Risk Assessment**: Categorizes messages as SAFE, MEDIUM, or HIGH risk
- 🔗 **Entity Extraction**: Identifies phone numbers, URLs, UPI IDs, emails, etc.
- 💬 **Stalling Replies**: Generates context-aware responses to engage scammers
- 🔐 **API Key Authentication**: Secure access control for your endpoint
- 📊 **Batch Processing**: Analyze up to 10 messages in a single request
- 🏥 **Health Checks**: Monitor API status and uptime
- ⚡ **Low Latency**: Optimized for fast response times
- 🛡️ **Security**: Helmet, CORS, and input validation

---

## 📦 Prerequisites

Before you begin, ensure you have:

1. **Node.js** (v18 or higher)
   ```bash
   node --version
   ```

2. **npm** or **yarn**
   ```bash
   npm --version
   ```

3. **Google Gemini API Key**
   - Get it from: [Google AI Studio](https://aistudio.google.com/)
   - It's free to start with generous quota

---

## 🚀 Quick Start

### Step 1: Navigate to Server Directory

```bash
cd server
```

### Step 2: Install Dependencies

```bash
npm install
```

### Step 3: Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` file with your actual values:

```env
PORT=3000
NODE_ENV=development
API_KEY=your_secure_api_key_here
GEMINI_API_KEY=your_google_gemini_api_key_here
CORS_ORIGIN=http://localhost:3000,http://localhost:5173
```

### Step 4: Start the Server

**Development mode (with auto-reload):**
```bash
npm run dev
```

**Production mode:**
```bash
npm run build
npm start
```

### Step 5: Verify the API is Running

Open your browser or use curl:

```bash
curl http://localhost:3000/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 0.5,
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

---

## 📁 Project Structure

```
scamguard_ai/
├── server/                    # Backend API server
│   ├── src/
│   │   ├── index.ts          # Main server entry point
│   │   ├── types.ts          # TypeScript type definitions
│   │   └── gemini-service.ts # Gemini AI integration
│   ├── package.json          # Dependencies and scripts
│   ├── tsconfig.json         # TypeScript configuration
│   ├── .env.example          # Environment template
│   └── .env                  # Environment variables (create this)
├── App.tsx                   # React frontend
├── components/               # React components
├── services/                 # Frontend services
├── index.html               # HTML entry point
└── README.md               # This file
```

---

## 📚 API Documentation

### Base URL

```
http://localhost:3000/api/v1
```

### Authentication

All analysis endpoints require API key authentication:

**Option 1: X-API-KEY Header**
```
X-API-KEY: your_api_key_here
```

**Option 2: Authorization Header**
```
Authorization: Bearer your_api_key_here
```

---

### Endpoints

#### 1. Analyze a Message

**POST** `/api/v1/analyze`

Analyzes a single message for scam indicators.

**Request Body:**
```json
{
  "message": "Urgent: Your bank account is blocked. Call 9998887776 immediately to resolve.",
  "timestamp": "2024-01-01T00:00:00Z",
  "sessionId": "optional-session-id"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "riskLevel": "HIGH",
    "score": 0.95,
    "classification": "Bank Fraud",
    "reasoning": [
      "Creates urgent panic to trigger quick action",
      "Requests immediate phone call to resolve issue",
      "No legitimate bank blocks accounts without prior notice"
    ],
    "entities": [
      {
        "type": "PHONE_NUMBER",
        "value": "9998887776"
      }
    ],
    "suggestedReply": "I'm concerned about this. Before I call, can you send me the official branch address so I can verify this is legitimate?",
    "agentState": "DELAY",
    "metadata": {
      "model": "gemini-3-flash-preview",
      "timestamp": "2024-01-01T00:00:00.000Z",
      "processingTime": 1500
    }
  },
  "meta": {
    "requestId": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-01-01T00:00:00.000Z",
    "processingTime": 1500
  }
}
```

---

#### 2. Batch Analysis

**POST** `/api/v1/analyze/batch`

Analyzes up to 10 messages in a single request.

**Request Body:**
```json
{
  "messages": [
    { "message": "Message 1..." },
    { "message": "Message 2..." }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "results": [
      {
        "index": 0,
        "success": true,
        "result": { /* AnalysisResult */ }
      },
      {
        "index": 1,
        "success": true,
        "result": { /* AnalysisResult */ }
      }
    ],
    "total": 2,
    "successful": 2,
    "failed": 0
  },
  "meta": {
    "requestId": "550e8400-e29b-41d4-a716-446655440000",
    "timestamp": "2024-01-01T00:00:00.000Z",
    "processingTime": 3000
  }
}
```

---

#### 3. Health Check

**GET** `/api/v1/health`

Returns API health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 123.45,
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

---

#### 4. API Information

**GET** `/api/v1`

Returns API documentation and available endpoints.

---

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | 3000 | Server port |
| `NODE_ENV` | No | development | Environment mode |
| `API_KEY` | No | - | Your API key for authentication |
| `GEMINI_API_KEY` | **Yes** | - | Google Gemini API key |
| `CORS_ORIGIN` | No | * | Comma-separated list of allowed origins |

### Getting Your Gemini API Key

1. Go to [Google AI Studio](https://aistudio.google.com/)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the generated key
5. Add it to your `.env` file

---

## 🧪 Testing the Endpoint

### Using curl

```bash
# Test health endpoint (no auth required)
curl http://localhost:3000/health

# Analyze a scam message
curl -X POST http://localhost:3000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: your_api_key_here" \
  -d '{
    "message": "Urgent: Your bank account is blocked. Call 9998887776 immediately."
  }'
```

### Using the Frontend Tester

The existing React app includes an **Endpoint Tester** component:
1. Start the server (`npm run dev`)
2. Start the frontend (`npm run dev` in root)
3. Go to the "Honeypot Tester" tab
4. Enter your endpoint URL and API key
5. Test your deployed endpoint

### Sample Test Cases

```json
// Bank Scam
{
  "message": "URGENT: Your account has been compromised. Verify your identity immediately at http://bit.ly/bank-verify or call 1800-SCAM immediately."
}

// Job Offer Scam
{
  "message": "Congratulations! You've been selected for a work-from-home job paying $5000/month. Send us your bank details to receive your first payment."
}

// UPI Scam
{
  "message": "Your UPI transaction of Rs.5000 failed. Please re-initiate from this link: http://upi-fraud.com/pay"
}
```

---

## 📊 Expected Results

When you successfully run the analysis, you should see:

### Successful Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Always `true` for successful requests |
| `data.riskLevel` | string | One of: `SAFE`, `MEDIUM`, `HIGH` |
| `data.score` | number | 0.0 (safe) to 1.0 (critical scam) |
| `data.classification` | string | Type of scam (e.g., "Bank Fraud") |
| `data.reasoning` | array | Array of explanation strings |
| `data.entities` | array | Extracted phone numbers, URLs, etc. |
| `data.suggestedReply` | string | Safe stalling reply for honey-pot |
| `data.agentState` | string | Strategy: `CONFUSE`, `DELAY`, or `EXTRACT` |
| `meta.requestId` | string | Unique request identifier |
| `meta.processingTime` | number | Time in milliseconds |

### Error Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `success` | boolean | Always `false` for errors |
| `error.code` | string | Error code (e.g., `UNAUTHORIZED`) |
| `error.message` | string | Human-readable error message |
| `error.details` | object | Additional error details (dev mode) |

---

## ✅ Evaluation Readiness Checklist

Before submitting your endpoint, verify:

- [ ] **API is Live**: `curl http://your-domain.com/health` returns 200 OK
- [ ] **Authentication Works**: Requests with valid API key succeed
- [ ] **Authentication Fails**: Requests without API key return 401/403
- [ ] **Correct Response Format**: JSON response matches the API spec
- [ ] **Low Latency**: Response time < 1 second (usually 1-2s with Gemini)
- [ ] **Error Handling**: Invalid requests return proper error messages
- [ ] **CORS Enabled**: Frontend testers can access your API
- [ ] **Stability**: API handles multiple requests reliably

### Submission Requirements

1. **Endpoint URL**: Must be a public HTTPS URL
2. **API Key**: Provide a valid key for authentication
3. **Stability**: Endpoint must be live during evaluation period
4. **Response Format**: Must match the defined JSON structure

---

## 🚀 Deployment

### Option 1: Railway (Recommended)

1. Push your code to GitHub
2. Connect to Railway
3. Set environment variables:
   - `GEMINI_API_KEY`: Your Gemini API key
   - `API_KEY`: Your desired API key
4. Deploy

### Option 2: Render

1. Connect your GitHub repository
2. Set build command: `cd server && npm install && npm run build`
3. Set start command: `cd server && npm start`
4. Add environment variables

### Option 3: Vercel

1. Create a `vercel.json` in the server directory:
```json
{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "framework": "typescript"
}
```

### Option 4: Fly.io

1. Create `Dockerfile`:
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
RUN npm run build
EXPOSE 3000
CMD ["npm", "start"]
```

2. Deploy with `fly deploy`

---

## 🛠️ Troubleshooting

### Common Issues

**"Cannot find module 'express'"**
```bash
cd server && npm install
```

**"GEMINI_API_KEY not set"**
- Get key from https://aistudio.google.com/
- Add to `.env` file

**"Connection refused"**
- Check if server is running on correct port
- Verify firewall allows traffic on the port

**"CORS error"**
- Add your domain to `CORS_ORIGIN` in `.env`
- Restart the server

### Debug Mode

Run with verbose logging:
```bash
DEBUG=* npm run dev
```

---

## 📝 License

MIT License - Feel free to use and modify for your submission.

---

## 🤝 Support

For issues or questions:
1. Check the troubleshooting section above
2. Review console logs for error messages
3. Ensure all environment variables are set correctly

---

**Good luck with your submission! 🛡️**

