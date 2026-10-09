// Test data for the Attack Lab's tests: API responses as the real API shapes them, with overrides for tampered ones.
import type { ToolExecution, ToolExecutionResult } from '@/features/agents'
import type { FirewallAnalysis, FirewallAnalysisResult } from '@/features/firewall'

export function analysis(overrides: Record<string, unknown> = {}): FirewallAnalysis {
  return {
    securityEventId: '0192a0f5-0000-7000-8000-00000000a001',
    decision: 'Block',
    reason: 'Risk meets the block threshold.',
    risk: { level: 'Critical', score: 95 },
    findings: [
      { code: 'InstructionOverride.IgnorePrevious', category: 'InstructionOverride', severity: 'High', confidence: 0.9, description: 'Ignore instructions.' },
      { code: 'SecretExtraction.SystemPromptDisclosure', category: 'SecretExtraction', severity: 'High', confidence: 0.9, description: 'Prompt.' },
    ],
    durationMs: 1.2,
    ...overrides,
  }
}

export function analysisResult(overrides: Record<string, unknown> = {}): FirewallAnalysisResult {
  return { analysis: analysis(overrides), correlationId: 'corr-lab-input', timestamp: '2026-10-07T09:00:00Z' }
}

export function execution(overrides: Record<string, unknown> = {}): ToolExecution {
  return {
    securityEventId: '0192a0f5-0000-7000-8000-00000000b001',
    decision: 'Allow',
    executed: true,
    outcome: 'Executed',
    authorizationReason: 'Permitted',
    riskLevel: 'Low',
    executionId: '0192a0f5-0000-7000-8000-00000000e001',
    result: { found: true, text: 'Dependency injection: from the dataset.' },
    approvalId: null,
    ...overrides,
  }
}

export function executionResult(overrides: Record<string, unknown> = {}): ToolExecutionResult {
  return { execution: execution(overrides), correlationId: 'corr-lab-tool', timestamp: '2026-10-07T09:00:01Z' }
}

/** A gateway Block of one kind: nothing ran, no grant, no result. */
export function stopped(decision: string, outcome: string, authorizationReason: string): Record<string, unknown> {
  return { decision, outcome, authorizationReason, executed: false, executionId: null, result: null }
}
