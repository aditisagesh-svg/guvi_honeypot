export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
}

export enum AgentState {
  IDLE = 'idle',
  ANALYZING = 'analyzing',
  ERROR = 'error',
}

export interface Entity {
  type: string;
  value: string;
}

export interface AnalysisResult {
  classification: string;
  score: number;
  reasoning: string[];
  entities: Entity[];
  risk: RiskLevel;
}

export interface HistoryItem {
  input: string;
  result: AnalysisResult;
  timestamp: number;
}

export interface TestResult {
  status: number;
  statusText: string;
  time: number;
  data: any;
  headers: Record<string, string>;
  error?: string;
}
