import { describe, expect, it } from 'vitest'
import type { AnalysisResult, Param, ProtocolInfo, TrafficLabel } from '@/types/analysis'
import { evaluate, policyById } from './rules'
import { computeRiskScore, riskBand } from './risk'
import { threatMatrix, categoryScores, severityCounts, matrixGrandTotal } from './threat'

const observed = <T>(value: T): Param<T> => ({ value, provenance: 'observed', confidence: 1 })
const inferred = <T>(value: T, confidence: number): Param<T> => ({
  value,
  provenance: 'inferred',
  confidence,
})

const classes = (...pairs: [TrafficLabel, number][]): { label: TrafficLabel; probability: number }[] =>
  pairs.map(([label, probability]) => ({ label, probability }))

/** Hand-built input for fixture A: modern IKEv2 + AES-GCM. */
const protocolA: ProtocolInfo = {
  ikeVersion: observed('IKEv2'),
  exchangeMode: observed('IKEv2 (IKE_SA_INIT + IKE_AUTH)'),
  mode: inferred('tunnel', 0.98),
  ipVersion: observed('IPv4'),
  natTraversal: observed(false),
  ike: {
    encryption: observed('AES-256-GCM-16'),
    integrity: observed('AEAD (implicit)'),
    prf: observed('PRF_HMAC_SHA2_384'),
    dhGroup: observed(14),
    lifetimeSec: observed(null),
  },
  child: {
    encryption: inferred('AES-256-GCM-16', 0.97),
    integrity: inferred('AEAD (implicit)', 0.97),
    pfs: inferred(true, 0.92),
    pfsGroup: inferred(14, 0.9),
    lifetimeSec: inferred(3600, 0.94),
    replayProtection: inferred(true, 0.96),
    esn: inferred(false, 0.89),
  },
}

const trafficA = classes(
  ['Web Browsing', 0.78],
  ['Video Streaming', 0.08],
  ['VoIP', 0.04],
  ['WhatsApp', 0.03],
  ['E-mail', 0.03],
  ['ICMP', 0.02],
  ['Other', 0.02],
)

/** Hand-built input for fixture B: IKEv2 with AES-CBC and SHA-1. */
const protocolB: ProtocolInfo = {
  ikeVersion: observed('IKEv2'),
  exchangeMode: observed('IKEv2 (IKE_SA_INIT + IKE_AUTH)'),
  mode: inferred('tunnel', 0.95),
  ipVersion: observed('IPv4'),
  natTraversal: observed(true),
  ike: {
    encryption: observed('AES-128-CBC'),
    integrity: observed('HMAC-SHA1-96'),
    prf: observed('PRF_HMAC_SHA1'),
    dhGroup: observed(2),
    lifetimeSec: observed(null),
  },
  child: {
    encryption: inferred('AES-128-CBC', 0.93),
    integrity: inferred('HMAC-SHA1-96', 0.9),
    pfs: inferred(false, 0.88),
    pfsGroup: inferred(null, 0.88),
    lifetimeSec: inferred(32400, 0.87),
    replayProtection: inferred(false, 0.81),
    esn: inferred(false, 0.85),
  },
}

const trafficB = classes(
  ['VoIP', 0.71],
  ['WhatsApp', 0.11],
  ['Video Streaming', 0.07],
  ['Web Browsing', 0.06],
  ['ICMP', 0.02],
  ['E-mail', 0.02],
  ['Other', 0.01],
)

/** Hand-built input for fixture C: obsolete IKEv1 Aggressive Mode with 3DES. */
const protocolC: ProtocolInfo = {
  ikeVersion: observed('IKEv1'),
  exchangeMode: observed('Aggressive Mode'),
  mode: inferred('transport', 0.82),
  ipVersion: observed('IPv6'),
  natTraversal: observed(false),
  ike: {
    encryption: observed('3DES-CBC'),
    integrity: observed('HMAC-SHA1-96'),
    prf: observed('PRF_HMAC_SHA1'),
    dhGroup: observed(1),
    lifetimeSec: observed(28800),
  },
  child: {
    encryption: inferred('3DES-CBC', 0.78),
    integrity: inferred('HMAC-SHA1-96', 0.74),
    pfs: inferred(false, 0.7),
    pfsGroup: inferred(null, 0.7),
    lifetimeSec: inferred(3600, 0.66),
    replayProtection: inferred(true, 0.72),
    esn: inferred(false, 0.69),
  },
}

const trafficC = classes(
  ['ICMP', 0.44],
  ['Web Browsing', 0.22],
  ['E-mail', 0.14],
  ['VoIP', 0.08],
  ['Video Streaming', 0.05],
  ['WhatsApp', 0.04],
  ['Other', 0.03],
)

const failIds = (findings: { ruleId: string }[]): string[] => findings.map((f) => f.ruleId).sort()

describe('rule engine exact scores', () => {
  it('scores fixture A inputs at 9 (LOW RISK) with R09, R10, R11', () => {
    const evaluation = evaluate(protocolA, trafficA)
    expect(failIds(evaluation.findings)).toEqual(['R09', 'R10', 'R11'])
    const score = computeRiskScore(evaluation.findings)
    expect(score).toBe(9)
    expect(riskBand(score)).toBe('low')
  })

  it('scores fixture B inputs at 78 (HIGH RISK) with the eight specified failures', () => {
    const evaluation = evaluate(protocolB, trafficB)
    expect(failIds(evaluation.findings)).toEqual(['R01', 'R04', 'R05', 'R06', 'R07', 'R08', 'R09', 'R10'])
    const score = computeRiskScore(evaluation.findings)
    expect(score).toBe(78)
    expect(riskBand(score)).toBe('high')
  })

  it('scores fixture C inputs at 94 (HIGH RISK) and does not fire R09', () => {
    const evaluation = evaluate(protocolC, trafficC)
    expect(failIds(evaluation.findings)).toEqual(['R01', 'R02', 'R03', 'R04', 'R07', 'R10'])
    const score = computeRiskScore(evaluation.findings)
    expect(score).toBe(94)
    expect(riskBand(score)).toBe('high')
  })

  it('does not fire R09 when the top class probability is below 0.6', () => {
    const evaluation = evaluate(protocolA, trafficC)
    const r09 = evaluation.outcomes.find((o) => o.ruleId === 'R09')
    // 0.44 is also below the default rule confidence of 0.6, so the rule is not evaluated.
    expect(r09?.result).toBe('unknown')
    expect(evaluation.findings.some((f) => f.ruleId === 'R09')).toBe(false)
  })

  it('fires R09 when the top class probability is high but below the rule confidence', () => {
    const evaluation = evaluate(protocolA, trafficB, policyById('nist-baseline'), 0.6)
    const r09 = evaluation.outcomes.find((o) => o.ruleId === 'R09')
    expect(r09?.result).toBe('fail')
  })
})

describe('confidence gating', () => {
  it('marks rules unknown when an inferred dependency is below the threshold', () => {
    const evaluation = evaluate(protocolC, trafficC, policyById('nist-baseline'), 0.99)
    const pfs = evaluation.outcomes.find((o) => o.ruleId === 'R04')
    expect(pfs?.result).toBe('unknown')
    expect(pfs?.evidence).toBe('Not evaluated: insufficient confidence in the underlying inference.')
    expect(evaluation.findings.some((f) => f.ruleId === 'R04')).toBe(false)
    expect(evaluation.counts.unknown).toBeGreaterThan(0)
  })

  it('keeps observed-parameter rules evaluated regardless of the threshold', () => {
    const evaluation = evaluate(protocolC, trafficC, policyById('nist-baseline'), 0.99)
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R03')?.result).toBe('fail')
  })

  it('evaluates R09 as unknown when the classifier confidence is low', () => {
    const evaluation = evaluate(protocolC, trafficC, policyById('nist-baseline'), 0.6)
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R09')?.result).toBe('unknown')
  })
})

describe('policy overrides', () => {
  it('raises R07 and R08 to high under the high-assurance policy', () => {
    const evaluation = evaluate(protocolB, trafficB, policyById('high-assurance'))
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R07')?.severity).toBe('high')
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R08')?.severity).toBe('high')
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R10')?.severity).toBe('medium')
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R11')?.severity).toBe('medium')
  })

  it('accepts a 32,400 s lifetime under legacy-interop and disables R08/R11', () => {
    const evaluation = evaluate(protocolB, trafficB, policyById('legacy-interop'))
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R06')?.result).toBe('pass')
    const r08 = evaluation.outcomes.find((o) => o.ruleId === 'R08')
    expect(r08?.result).toBe('unknown')
    expect(r08?.evidence).toContain('Not evaluated under policy')
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R11')?.result).toBe('unknown')
  })

  it('fails R06 earlier under high-assurance (14,400 s)', () => {
    const evaluation = evaluate(protocolB, trafficB, policyById('high-assurance'))
    expect(evaluation.outcomes.find((o) => o.ruleId === 'R06')?.result).toBe('fail')
  })
})

describe('threat matrix and category scores', () => {
  it('builds a 4 x 7 matrix whose totals match the findings', () => {
    const evaluation = evaluate(protocolB, trafficB)
    const matrix = threatMatrix(evaluation.findings)
    expect(matrix.critical['Key Exchange']).toBe(1)
    expect(matrix.high.PFS).toBe(1)
    expect(matrix.high.Replay).toBe(1)
    expect(matrix.high.Lifetime).toBe(1)
    expect(matrix.medium['Weak Cipher']).toBe(2)
    expect(matrix.medium.Metadata).toBe(1)
    expect(matrix.low.Replay).toBe(1)
    expect(matrixGrandTotal(matrix)).toBe(evaluation.findings.length)
    expect(severityCounts(evaluation.findings)).toEqual({ critical: 1, high: 3, medium: 3, low: 1 })
  })

  it('returns safety scores of 100 - min(100, weight sum) per category', () => {
    const evaluation = evaluate(protocolB, trafficB)
    const scores = categoryScores(evaluation.findings)
    expect(scores['Key Exchange']).toBe(75) // 100 - 25
    expect(scores.PFS).toBe(88) // 100 - 12
    expect(scores['Weak Cipher']).toBe(90) // 100 - (5 + 5)
    expect(scores.Protocol).toBe(100)
  })
})

describe('risk scoring', () => {
  it('caps the score at 100', () => {
    const findings = Array.from({ length: 8 }, () => ({ severity: 'critical' as const }))
    expect(computeRiskScore(findings)).toBe(100)
  })

  it('bands scores at 40 and 70', () => {
    expect(riskBand(39)).toBe('low')
    expect(riskBand(40)).toBe('moderate')
    expect(riskBand(69)).toBe('moderate')
    expect(riskBand(70)).toBe('high')
  })
})

describe('evaluation reuse', () => {
  it('produces a Finding list shaped for the data contract', () => {
    const evaluation = evaluate(protocolB, trafficB)
    const finding = evaluation.findings[0]
    expect(finding).toBeDefined()
    if (!finding) throw new Error('expected findings')
    expect(finding.status).toBe('fail')
    expect(finding.reference.length).toBeGreaterThan(0)
    expect(finding.evidence).not.toContain('undefined')
    const asResult: Pick<AnalysisResult, 'findings'> = { findings: evaluation.findings }
    expect(asResult.findings.length).toBe(8)
  })
})
