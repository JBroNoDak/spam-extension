/**
 * Type definitions for Gmail Phishing Guard
 */

export type RiskLevel = 'safe' | 'caution' | 'warning' | 'critical';

export interface EmailSender {
  name: string;
  email: string;
  domain: string;
  avatarUrl?: string;
  isExternal: boolean;
}

export interface EmailLink {
  url: string;
  text: string;
  issues?: string[];
  riskLevel?: RiskLevel;
  score?: number;
}

export interface EmailAttachment {
  id: string;
  filename: string;
  size: string;
  type: string;
  issues?: string[];
  riskLevel?: RiskLevel;
  score?: number;
}

export interface EmailHeaders {
  spf: 'pass' | 'fail' | 'neutral' | 'none';
  dkim: 'pass' | 'fail' | 'neutral' | 'none';
  dmarc: 'pass' | 'fail' | 'neutral' | 'none';
  returnPath?: string;
  ipAddress?: string;
  deliveredTo?: string;
}

export interface AIAnalysisResult {
  isPhishing: boolean;
  confidence: number;
  threatCategory: string;
  reasoning: string;
  socialEngineeringTactics: string[];
  recommendations: string[];
}

export interface EmailScanReport {
  overallRiskLevel: RiskLevel;
  overallScore: number;
  isExternal: boolean;
  heuristicSignals: string[];
  links: EmailLink[];
  attachments: EmailAttachment[];
  aiAnalysis?: AIAnalysisResult | null;
  timestamp: string;
}

export interface EmailMessage {
  id: string;
  sender: EmailSender;
  recipient: string;
  date: string;
  subject: string;
  snippet: string;
  bodyHtml: string;
  bodyText: string;
  isExternal: boolean;
  headers: EmailHeaders;
  attachments: EmailAttachment[];
  tags: string[];
  isStarred?: boolean;
  isRead?: boolean;
}

export interface ExtensionSettings {
  enabled: boolean;
  sensitivity: 'strict' | 'balanced' | 'permissive';
  interceptCriticalClicks: boolean;
  whitelist: string[];
  highlightLinks: boolean;
  highlightAttachments: boolean;
  showBanner: boolean;
}
