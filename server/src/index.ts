import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';

// Load environment variables
dotenv.config();

// Import types and services
import {
  AnalysisResult,
  AnalyzeRequest,
  ApiResponse,
  HealthCheckResponse,
  ErrorCode,
  RiskLevel,
} from './types';
import { GeminiService } from './gemini-service';

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Initialize Gemini service
const geminiService = new GeminiService(process.env.GEMINI_API_KEY || '');

// ============================================================================
// MIDDLEWARE
// ============================================================================

// Security headers
app.use(helmet());

// CORS configuration
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(',') || '*',
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-KEY'],
    credentials: true,
  })
);

// Request logging
app.use(morgan('combined'));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

/**
 * API Key authentication middleware
 * Validates the API key from X-API-KEY header or Authorization header
 */
const authenticateApiKey = (req: Request, res: Response, next: NextFunction): void => {
  const apiKey = req.headers['x-api-key'] as string;
  const authHeader = req.headers['authorization'] as string;

  // Check for API key in X-API-KEY header
  let providedKey: string | undefined;
  if (apiKey) {
    providedKey = apiKey;
  }
  // Check for API key in Authorization header (Bearer token)
  else if (authHeader?.startsWith('Bearer ')) {
    providedKey = authHeader.substring(7);
  }

  // Validate API key
  const validKey = process.env.API_KEY;
  if (!validKey) {
    // If no API key is set in environment, allow access (development mode)
    console.warn('WARNING: No API_KEY set in environment. Authentication disabled.');
    return next();
  }

  if (!providedKey) {
    const response: ApiResponse<null> = {
      success: false,
      error: {
        code: ErrorCode.UNAUTHORIZED,
        message: 'API key is required. Provide it in X-API-KEY header or Authorization: Bearer <key>',
      },
      meta: {
        requestId: uuidv4(),
        timestamp: new Date().toISOString(),
        processingTime: 0,
      },
    };
    res.status(401).json(response);
    return;
  }

  if (providedKey !== validKey) {
    const response: ApiResponse<null> = {
      success: false,
      error: {
        code: ErrorCode.FORBIDDEN,
        message: 'Invalid API key provided',
      },
      meta: {
        requestId: uuidv4(),
        timestamp: new Date().toISOString(),
        processingTime: 0,
      },
    };
    res.status(403).json(response);
    return;
  }

  next();
};

// ============================================================================
// REQUEST VALIDATION
// ============================================================================

/**
 * Validates the analyze request body
 */
const validateAnalyzeRequest = (req: Request, res: Response, next: NextFunction): void => {
  const body = req.body as AnalyzeRequest;

  if (!body.message) {
    const response: ApiResponse<null> = {
      success: false,
      error: {
        code: ErrorCode.VALIDATION_ERROR,
        message: 'Message field is required in request body',
        details: { field: 'message' },
      },
      meta: {
        requestId: uuidv4(),
        timestamp: new Date().toISOString(),
        processingTime: 0,
      },
    };
    res.status(400).json(response);
    return;
  }

  if (typeof body.message !== 'string') {
    const response: ApiResponse<null> = {
      success: false,
      error: {
        code: ErrorCode.VALIDATION_ERROR,
        message: 'Message must be a string',
        details: { field: 'message', type: typeof body.message },
      },
      meta: {
        requestId: uuidv4(),
        timestamp: new Date().toISOString(),
        processingTime: 0,
      },
    };
    res.status(400).json(response);
    return;
  }

  if (body.message.length > 10000) {
    const response: ApiResponse<null> = {
      success: false,
      error: {
        code: ErrorCode.VALIDATION_ERROR,
        message: 'Message is too long. Maximum length is 10,000 characters',
        details: { field: 'message', maxLength: 10000 },
      },
      meta: {
        requestId: uuidv4(),
        timestamp: new Date().toISOString(),
        processingTime: 0,
      },
    };
    res.status(400).json(response);
    return;
  }

  next();
};

// ============================================================================
// ROUTES
// ============================================================================

// Root health check (no authentication required)
app.get('/', (req: Request, res: Response): void => {
  const healthCheck: HealthCheckResponse = {
    status: 'healthy',
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  };
  res.json(healthCheck);
});

// Detailed health check endpoint
app.get('/health', (req: Request, res: Response): void => {
  const healthCheck: HealthCheckResponse = {
    status: 'healthy',
    version: '1.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  };
  res.json(healthCheck);
});

// API information endpoint
app.get('/api/v1', (req: Request, res: Response): void => {
  res.json({
    name: 'ScamGuard AI - Agentic Honey-Pot API',
    version: '1.0.0',
    description: 'API for scam message analysis and intelligence extraction',
    endpoints: {
      'POST /api/v1/analyze': 'Analyze a message for scam indicators',
      'GET /api/v1/health': 'Health check endpoint',
    },
    authentication: {
      type: 'API Key',
      header: 'X-API-KEY',
      alternative: 'Authorization: Bearer <api-key>',
    },
    rateLimit: '100 requests per minute',
  });
});

// ============================================================================
// MAIN ENDPOINT - Analyze Message
// ============================================================================

/**
 * POST /api/v1/analyze
 * 
 * Analyzes a message for potential scam activity and returns extracted intelligence.
 * 
 * Request body:
 * {
 *   "message": "Urgent: Your bank account is blocked. Call 9998887776...",
 *   "timestamp": "2024-01-01T00:00:00Z", // optional
 *   "sessionId": "session-123" // optional
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "data": {
 *     "riskLevel": "HIGH",
 *     "score": 0.95,
 *     "classification": "Bank Fraud",
 *     "reasoning": ["Urgency tactics", "Request for immediate action"],
 *     "entities": [{"type": "PHONE_NUMBER", "value": "9998887776"}],
 *     "suggestedReply": "I'm not sure about this. Can you verify?",
 *     "agentState": "DELAY"
 *   },
 *   "meta": {
 *     "requestId": "uuid-v4",
 *     "timestamp": "2024-01-01T00:00:00Z",
 *     "processingTime": 1500
 *   }
 * }
 */
app.post(
  '/api/v1/analyze',
  authenticateApiKey,
  validateAnalyzeRequest,
  async (req: Request, res: Response): Promise<void> => {
    const requestId = uuidv4();
    const startTime = Date.now();

    try {
      const body = req.body as AnalyzeRequest;
      
      console.log(`[${requestId}] Analyzing message: "${body.message.substring(0, 100)}..."`);

      // Analyze the message using Gemini
      const analysis: AnalysisResult = await geminiService.analyzeMessage(body.message);

      const processingTime = Date.now() - startTime;

      // Build response
      const response: ApiResponse<AnalysisResult> = {
        success: true,
        data: analysis,
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
          processingTime,
        },
      };

      console.log(`[${requestId}] Analysis complete. Risk: ${analysis.riskLevel}, Score: ${analysis.score}, Time: ${processingTime}ms`);

      res.json(response);
    } catch (error) {
      const processingTime = Date.now() - startTime;
      console.error(`[${requestId}] Error analyzing message:`, error);

      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';

      const response: ApiResponse<null> = {
        success: false,
        error: {
          code: ErrorCode.INTERNAL_ERROR,
          message: 'Failed to analyze message',
          details: process.env.NODE_ENV === 'development' ? errorMessage : undefined,
        },
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
          processingTime,
        },
      };

      res.status(500).json(response);
    }
  }
);

// ============================================================================
// BATCH ENDPOINT - Analyze Multiple Messages
// ============================================================================

/**
 * POST /api/v1/analyze/batch
 * 
 * Analyzes multiple messages in a single request.
 * 
 * Request body:
 * {
 *   "messages": [
 *     {"message": "Message 1..."},
 *     {"message": "Message 2..."}
 *   ]
 * }
 */
app.post(
  '/api/v1/analyze/batch',
  authenticateApiKey,
  async (req: Request, res: Response): Promise<void> => {
    const requestId = uuidv4();
    const startTime = Date.now();

    try {
      const body = req.body;
      
      if (!Array.isArray(body.messages)) {
        const response: ApiResponse<null> = {
          success: false,
          error: {
            code: ErrorCode.VALIDATION_ERROR,
            message: 'messages field must be an array',
          },
          meta: {
            requestId,
            timestamp: new Date().toISOString(),
            processingTime: 0,
          },
        };
        res.status(400).json(response);
        return;
      }

      if (body.messages.length > 10) {
        const response: ApiResponse<null> = {
          success: false,
          error: {
            code: ErrorCode.VALIDATION_ERROR,
            message: 'Maximum 10 messages per batch request',
            details: { maxBatchSize: 10, requestedSize: body.messages.length },
          },
          meta: {
            requestId,
            timestamp: new Date().toISOString(),
            processingTime: 0,
          },
        };
        res.status(400).json(response);
        return;
      }

      console.log(`[${requestId}] Batch analyzing ${body.messages.length} messages`);

      // Analyze all messages in parallel
      const results = await Promise.all(
        body.messages.map(async (msg: any, index: number) => {
          try {
            return {
              index,
              success: true,
              result: await geminiService.analyzeMessage(msg.message),
            };
          } catch (error) {
            return {
              index,
              success: false,
              error: error instanceof Error ? error.message : 'Unknown error',
            };
          }
        })
      );

      const processingTime = Date.now() - startTime;

      const response: ApiResponse<{
        results: typeof results;
        total: number;
        successful: number;
        failed: number;
      }> = {
        success: true,
        data: {
          results,
          total: results.length,
          successful: results.filter((r: any) => r.success).length,
          failed: results.filter((r: any) => !r.success).length,
        },
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
          processingTime,
        },
      };

      res.json(response);
    } catch (error) {
      const processingTime = Date.now() - startTime;
      console.error(`[${requestId}] Error in batch analysis:`, error);

      const response: ApiResponse<null> = {
        success: false,
        error: {
          code: ErrorCode.INTERNAL_ERROR,
          message: 'Failed to process batch request',
        },
        meta: {
          requestId,
          timestamp: new Date().toISOString(),
          processingTime,
        },
      };

      res.status(500).json(response);
    }
  }
);

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler
app.use((req: Request, res: Response): void => {
  const requestId = uuidv4();
  const response: ApiResponse<null> = {
    success: false,
    error: {
      code: ErrorCode.NOT_FOUND,
      message: `Route ${req.method} ${req.path} not found`,
    },
    meta: {
      requestId,
      timestamp: new Date().toISOString(),
      processingTime: 0,
    },
  };
  res.status(404).json(response);
});

// Global error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction): void => {
  const requestId = uuidv4();
  console.error(`[${requestId}] Unhandled error:`, err);

  const response: ApiResponse<null> = {
    success: false,
    error: {
      code: ErrorCode.INTERNAL_ERROR,
      message: 'An unexpected error occurred',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined,
    },
    meta: {
      requestId,
      timestamp: new Date().toISOString(),
      processingTime: 0,
    },
  };

  res.status(500).json(response);
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🛡️  ScamGuard AI - Agentic Honey-Pot API                   ║
║   =========================================                   ║
║                                                               ║
║   Server running on: http://localhost:${PORT}                   ║
║   API Base URL:      http://localhost:${PORT}/api/v1            ║
║   Health Check:      http://localhost:${PORT}/health             ║
║                                                               ║
║   Endpoints:                                                   ║
║   - POST /api/v1/analyze     Analyze scam messages            ║
║   - POST /api/v1/analyze/batch  Batch analysis (max 10)       ║
║   - GET  /api/v1/health      Health check                     ║
║   - GET  /api/v1             API information                  ║
║                                                               ║
║   Authentication:                                             ║
║   Header: X-API-KEY: <your-api-key>                           ║
║   Or: Authorization: Bearer <your-api-key>                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
  `);

  if (!process.env.GEMINI_API_KEY) {
    console.warn('⚠️  WARNING: GEMINI_API_KEY not set in environment variables!');
    console.warn('   Please set it before making analysis requests.');
    console.warn('   Get your API key from: https://aistudio.google.com/');
  }

  if (!process.env.API_KEY) {
    console.warn('⚠️  WARNING: API_KEY not set in environment variables!');
    console.warn('   Authentication is currently DISABLED for development.');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

export default app;

