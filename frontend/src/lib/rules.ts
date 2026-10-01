import type { AnalysisResult, Finding, ProtocolInfo, Severity, TrafficLabel, PolicyId } from '@/types/analysis'
import type { Policy } from '@/types/misc'
import { BASELINE_RULES, getParam, UNKNOWN_EVIDENCE } from './ruleDefs'
import type { Rule, RuleContext, RuleResult } from './ruleDefs'

export type { Rule, RuleContext, RuleResult, RuleParamKey } from './ruleDefs'
export { BASELINE_RULES, topClass } from './ruleDefs'

/** Baseline CHILD SA lifetime maximum in seconds (spec 7.1, rule R06). */
export const BASELINE_LIFETIME_MAX_SEC = 28_800

export const POLICIES: Policy[] = [
  {
    id: 'nist-baseline',
    name: 'NIST SP 800-77 Rev. 1 baseline',
    summary: 'The default rule table exactly as specified; no overrides.',
    overrides: { childLifetimeMaxSec: BASELINE_LIFETIME_MAX_SEC, severity: {}, disabled: [] },
  },
  {
    id: 'high-assurance',
    name: 'High assurance',
    summary: 'Shorter lifetimes and stricter severity for legacy algorithms.',
    overrides: {
      childLifetimeMaxSec: 14_400,
      severity: { R07: 'high', R08: 'high', R10: 'medium', R11: 'medium' },
      disabled: [],
    },
  },
  {
    id: 'legacy-interop',
    name: 'Legacy interoperability',
    summary: 'Relaxed lifetimes for ageing peers; R08 and R11 are not evaluated.',
    overrides: {
      childLifetimeMaxSec: 86_400,
      severity: { R07: 'low' },
      disabled: ['R08', 'R11'],
    },
  },
]

export function policyById(id: PolicyId): Policy {
  return POLICIES.find((p) => p.id === id) ?? POLICIES[0]
}

export const DEFAULT_POLICY: Policy = POLICIES[0]

export interface RuleOutcome {
  ruleId: string
  title: string
  /** Severity after policy overrides. */
  severity: Severity
  category: Rule['category']
  stride: Rule['stride']
  result: RuleResult
  evidence: string
  reference: string
  recommendation: string
}

export interface Evaluation {
  outcomes: RuleOutcome[]
  findings: Finding[]
  counts: { pass: number; fail: number; unknown: number; total: number }
}

export interface EvaluateOptions {
  policy?: Policy
  minRuleConfidence?: number
}

/**
 * The single source for findings, risk score, threat matrix and compliance.
 * A rule that depends on an inferred parameter returns `unknown` when that
 * parameter's confidence is below `minRuleConfidence` (default 0.6).
 */
export function evaluate(
  protocol: ProtocolInfo,
  trafficClasses: { label: TrafficLabel; probability: number }[],
  policy: Policy = DEFAULT_POLICY,
  minRuleConfidence = 0.6,
): Evaluation {
  const ctx: RuleContext = {
    protocol,
    trafficClasses,
    childLifetimeMaxSec: policy.overrides.childLifetimeMaxSec ?? BASELINE_LIFETIME_MAX_SEC,
    minRuleConfidence,
  }

  const outcomes: RuleOutcome[] = BASELINE_RULES.map((rule) => {
    const severity = policy.overrides.severity?.[rule.id] ?? rule.severity
    const base = {
      ruleId: rule.id,
      title: rule.title,
      severity,
      category: rule.category,
      stride: rule.stride,
      reference: rule.reference,
      recommendation: rule.recommendation,
    }

    if (policy.overrides.disabled?.includes(rule.id)) {
      return { ...base, result: 'unknown' as const, evidence: `Not evaluated under policy "${policy.name}".` }
    }

    const lowConfidence = rule.dependsOn.some((key) => {
      const param = getParam(ctx, key)
      return param !== null && param.provenance === 'inferred' && param.confidence < minRuleConfidence
    })
    if (lowConfidence) {
      return { ...base, result: 'unknown' as const, evidence: UNKNOWN_EVIDENCE }
    }

    const checked = rule.check(ctx)
    return { ...base, result: checked.result, evidence: checked.evidence }
  })

  const findings: Finding[] = outcomes
    .filter((o) => o.result === 'fail')
    .map((o) => ({
      id: `finding-${o.ruleId}`,
      ruleId: o.ruleId,
      severity: o.severity,
      category: o.category,
      stride: o.stride,
      title: o.title,
      evidence: o.evidence,
      reference: o.reference,
      recommendation: o.recommendation,
      status: 'fail' as const,
    }))

  const counts = {
    pass: outcomes.filter((o) => o.result === 'pass').length,
    fail: outcomes.filter((o) => o.result === 'fail').length,
    unknown: outcomes.filter((o) => o.result === 'unknown').length,
    total: outcomes.length,
  }

  return { outcomes, findings, counts }
}

/** Convenience: baseline evaluation over a stored analysis. */
export function evaluateAnalysis(
  analysis: Pick<AnalysisResult, 'protocol' | 'trafficClasses'>,
  options: EvaluateOptions = {},
): Evaluation {
  return evaluate(
    analysis.protocol,
    analysis.trafficClasses,
    options.policy ?? DEFAULT_POLICY,
    options.minRuleConfidence ?? 0.6,
  )
}
