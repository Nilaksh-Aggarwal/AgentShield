import { apiClient } from '@/services/api'

export type SecurityDecision = 'Allow' | 'Review' | 'Block'
export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical'
export type ThreatSeverity = 'Low' | 'Medium' | 'High' | 'Critical'
/** `InconclusiveAnalysis` is not an attack: part of the analysis could not complete, so the input is held for review. */
export type ThreatCategory =
  | 'InstructionOverride'
  | 'RoleManipulation'
  | 'SecretExtraction'
  | 'Obfuscation'
  | 'InconclusiveAnalysis'

/** Mirrors the backend validator; the backend remains authoritative (422 if exceeded). */
export const MAX_INPUT_LENGTH = 32_000

export interface AnalyzeInputRequest {
  input: string
}

export interface ThreatFinding {
  code: string
  category: ThreatCategory
  severity: ThreatSeverity
  /** Detector author's heuristic estimate (0–1) that a match is a real attack; not a calibrated probability. */
  confidence: number
  description: string
}

export interface FirewallAnalysis {
  securityEventId: string
  decision: SecurityDecision
  reason: string
  risk: { level: RiskLevel; score: number }
  /** Duplicates fused; most severe first, then category, then code. */
  findings: ThreatFinding[]
  durationMs: number
}

/** An analysis together with the response metadata needed to trace it. */
export interface FirewallAnalysisResult {
  analysis: FirewallAnalysis
  /** Request trace ID (`meta.correlationId`); distinct from the analysis's security event ID. */
  correlationId: string
  /** When the API produced the response (`meta.timestamp`, ISO 8601). */
  timestamp: string
}

/**
 * POST /api/v1/firewall/analyze — any decision (including Block) is a 200 response. `correlationId` sends the analysis in a
 * given trace, so a tool call in the same trace can reference its security event.
 */
export async function analyzeInput(request: AnalyzeInputRequest, signal?: AbortSignal, correlationId?: string): Promise<FirewallAnalysisResult> {
  const { data, meta } = await apiClient.postForEnvelope<FirewallAnalysis>('/api/v1/firewall/analyze', request, {
    signal,
    headers: correlationId === undefined ? undefined : { 'X-Correlation-ID': correlationId },
  })
  return { analysis: data, correlationId: meta.correlationId, timestamp: meta.timestamp }
}
