// Risk level enumeration
export enum RiskLevel {
  SAFE = 'SAFE',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
}

// Agent state enumeration for conversation strategy
export enum AgentState {
  CONFUSE = 'CONFUSE',
  DELAY = 'DELAY',
  EXTRACT = 'EXTRACT',
  SAFE_EXIT = 'SAFE_EXIT',
}

// Entity types that can be extracted from scam messages
export enum EntityType {
  UPI_ID = 'UPI_ID',
  PHONE_NUMBER = 'PHONE_NUMBER',
  URL = 'URL',
  ORG = 'ORG',
  IFSC = 'IFSC',
  PERSON = 'PERSON',
  EMAIL = 'EMAIL',
  BANK_ACCOUNT = 'BANK_ACCOUNT',
}

// Entity interface
export interface Entity {
  type: EntityType;
  value: string;
  confidence?: number;
}

// Main analysis result interface
export interface AnalysisResult {
  riskLevel: RiskLevel;
  score: number; // 0.0 to 1.0
  classification: string; // e.g., "Bank Fraud", "Job Offer Scam", etc.
  reasoning: string[]; // Array of reasons for the classification
  entities: Entity[]; // Extracted entities from the message
  suggestedReply: string; // Safe stalling reply for honey-pot
  agentState: AgentState; // Conversation strategy state
  metadata?: {
    model?: string;
    timestamp?: string;
    processingTime?: number;
  };
}

// Request interface
export interface AnalyzeRequest {
  message: string;
  timestamp?: string;
  sessionId?: string;
}

// Response interface
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  meta?: {
    requestId: string;
    timestamp: string;
    processingTime: number;
  };
}

// Error codes
export enum ErrorCode {
  INVALID_REQUEST = 'INVALID_REQUEST',
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  NOT_FOUND = 'NOT_FOUND',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  RATE_LIMITED = 'RATE_LIMITED',
  VALIDATION_ERROR = 'VALIDATION_ERROR',
}

// Health check response
export interface HealthCheckResponse {
  status: 'healthy' | 'unhealthy';
  version: string;
  uptime: number;
  timestamp: string;
}

