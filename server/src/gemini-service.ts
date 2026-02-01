import { GoogleGenAI, Type } from '@google/genai';
import {
  AnalysisResult,
  RiskLevel,
  AgentState,
  Entity,
  EntityType,
} from './types';

/**
 * GeminiService handles all interactions with Google's Gemini AI model
 * for scam message analysis and intelligence extraction
 */
export class GeminiService {
  private client: GoogleGenAI;
  private model: string = 'gemini-3-flash-preview';

  constructor(apiKey: string) {
    this.client = new GoogleGenAI({ apiKey });
  }

  /**
   * Schema for the expected response from Gemini
   */
  private getAnalysisSchema() {
    return {
      type: Type.OBJECT,
      properties: {
        riskLevel: {
          type: Type.STRING,
          description: 'One of SAFE, MEDIUM, HIGH',
        },
        score: {
          type: Type.NUMBER,
          description: 'Numerical risk score from 0.0 (Safe) to 1.0 (Critical Scam)',
        },
        classification: {
          type: Type.STRING,
          description: 'Type of scam, e.g., Bank Fraud, Job Offer, Lottery Scam',
        },
        reasoning: {
          type: Type.ARRAY,
          items: { type: Type.STRING },
          description: 'Array of strings explaining why this was classified as a scam',
        },
        entities: {
          type: Type.ARRAY,
          items: {
            type: Type.OBJECT,
            properties: {
              type: { type: Type.STRING },
              value: { type: Type.STRING },
            },
          },
          description: 'Extracted entities like phone numbers, URLs, UPI IDs',
        },
        suggestedReply: {
          type: Type.STRING,
          description: 'A safe, stalling response to waste the scammer\'s time',
        },
        agentState: {
          type: Type.STRING,
          description: 'The conversation strategy state (CONFUSE, DELAY, EXTRACT)',
        },
      },
      required: [
        'riskLevel',
        'score',
        'classification',
        'reasoning',
        'entities',
        'suggestedReply',
        'agentState',
      ],
    };
  }

  /**
   * Analyzes a message for potential scam activity
   * @param message - The message to analyze
   * @returns AnalysisResult with risk assessment and extracted intelligence
   */
  async analyzeMessage(message: string): Promise<AnalysisResult> {
    const startTime = Date.now();

    try {
      const response = await this.client.models.generateContent({
        model: this.model,
        contents: `You are a scam detection and honey-pot engagement AI. Your task is to analyze incoming messages for scam indicators and provide intelligence for an agentic honey-pot system.

Message to analyze: "${message}"

Please provide a comprehensive analysis:

1. **Risk Assessment**: Determine if this is SAFE, MEDIUM, or HIGH risk scam
2. **Classification**: Identify the specific type of scam
3. **Reasoning**: Explain why this is suspicious or not
4. **Entities**: Extract all identifiable entities (phone numbers, URLs, UPI IDs, etc.)
5. **Agent Strategy**: Suggest CONFUSE, DELAY, or EXTRACT strategy
6. **Stalling Reply**: Generate a realistic, non-committal reply to keep the scammer engaged

Be thorough in entity extraction and reasoning.`,
        config: {
          responseMimeType: 'application/json',
          responseSchema: this.getAnalysisSchema(),
        },
      });

      const processingTime = Date.now() - startTime;
      const rawResult = JSON.parse(response.text || '{}');

      // Validate and normalize the response
      const result = this.normalizeAnalysisResult(rawResult, processingTime);

      return result;
    } catch (error) {
      console.error('Error analyzing message:', error);
      throw new Error(`Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Normalizes and validates the raw response from Gemini
   */
  private normalizeAnalysisResult(raw: any, processingTime: number): AnalysisResult {
    // Validate required fields
    if (!raw.riskLevel || !raw.classification) {
      throw new Error('Invalid response from AI model: missing required fields');
    }

    // Normalize risk level
    let riskLevel: RiskLevel;
    switch (raw.riskLevel.toUpperCase()) {
      case 'SAFE':
        riskLevel = RiskLevel.SAFE;
        break;
      case 'MEDIUM':
        riskLevel = RiskLevel.MEDIUM;
        break;
      case 'HIGH':
        riskLevel = RiskLevel.HIGH;
        break;
      default:
        riskLevel = RiskLevel.SAFE;
    }

    // Normalize agent state
    let agentState: AgentState;
    switch (raw.agentState?.toUpperCase()) {
      case 'CONFUSE':
        agentState = AgentState.CONFUSE;
        break;
      case 'DELAY':
        agentState = AgentState.DELAY;
        break;
      case 'EXTRACT':
        agentState = AgentState.EXTRACT;
        break;
      default:
        agentState = AgentState.DELAY; // Default to DELAY strategy
    }

    // Normalize entities
    const entities: Entity[] = Array.isArray(raw.entities)
      ? raw.entities.map((e: any) => ({
          type: this.normalizeEntityType(e.type),
          value: e.value || '',
          confidence: e.confidence,
        }))
      : [];

    return {
      riskLevel,
      score: Math.max(0, Math.min(1, parseFloat(raw.score) || 0)),
      classification: raw.classification || 'Unknown',
      reasoning: Array.isArray(raw.reasoning) ? raw.reasoning : ['No reasoning provided'],
      entities,
      suggestedReply: raw.suggestedReply || 'I need to verify this information. Can you provide more details?',
      agentState,
      metadata: {
        model: this.model,
        timestamp: new Date().toISOString(),
        processingTime,
      },
    };
  }

  /**
   * Normalizes entity type strings to EntityType enum
   */
  private normalizeEntityType(type: string): EntityType {
    const normalized = type?.toUpperCase().replace(/[- ]/g, '_');
    
    switch (normalized) {
      case 'UPI_ID':
      case 'UPI':
        return EntityType.UPI_ID;
      case 'PHONE_NUMBER':
      case 'PHONE':
      case 'MOBILE':
        return EntityType.PHONE_NUMBER;
      case 'URL':
      case 'LINK':
      case 'WEBSITE':
        return EntityType.URL;
      case 'ORG':
      case 'ORGANIZATION':
      case 'COMPANY':
        return EntityType.ORG;
      case 'IFSC':
        return EntityType.IFSC;
      case 'PERSON':
      case 'NAME':
        return EntityType.PERSON;
      case 'EMAIL':
        return EntityType.EMAIL;
      case 'BANK_ACCOUNT':
      case 'ACCOUNT':
        return EntityType.BANK_ACCOUNT;
      default:
        return EntityType.PERSON;
    }
  }

  /**
   * Health check for the Gemini service
   */
  async healthCheck(): Promise<boolean> {
    try {
      // Simple check to see if we can communicate with Gemini
      await this.client.models.list();
      return true;
    } catch (error) {
      console.error('Gemini health check failed:', error);
      return false;
    }
  }
}

