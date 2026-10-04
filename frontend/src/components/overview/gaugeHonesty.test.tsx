/**
 * v1.2.5 Part A tests (test-first): gauge track token, Method column
 * completeness, confidence microcopy, severity-coloured waterfall bars.
 */
import { render, screen, within } from '@testing-library/react'
import { describe, expect, it, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { mapAnalyzeResponse, type BackendAnalyzeResponse } from '@/api/backend'
import { RiskGauge } from '@/components/overview/RiskGauge'
import { KpiBar } from '@/components/overview/KpiBar'
import { getFixture } from '@/api/fixtures'
import { useSentinel } from '@/store/useSentinel'

type Status = 'OBSERVED' | 'INFERRED' | 'UNKNOWN' | 'NOT_OBSERVED' | 'NOT_APPLICABLE'
function field(value: unknown, source: 'parsed' | 'model' | 'measured' | 'none' = 'parsed', confidence = 1, status: Status = 'OBSERVED', evidence: Record<string, unknown> | null = null) {
  return { value, source, confidence, status, detail: null, evidence }
}

function v21resp(): BackendAnalyzeResponse {
  return {
    fields: {
      traffic_type: field('voip', 'model', 1, 'INFERRED'),
      ip_version: field(4, 'parsed', 1, 'OBSERVED'),
      nat_t: field(false, 'parsed', 1, 'OBSERVED'),
    },
    ike_sa: {
      version: field('ikev2', 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
      enc_alg: field('3des-cbc', 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
      enc_key_len: field(168, 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
      auth_alg: field('hmac-sha1', 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
      prf: field('hmac-sha1', 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
      dh_group: field(2, 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
    },
    child_sa: {
      proto: field('esp'),
      mode: { value: 'tunnel', source: 'model', confidence: 0.99, status: 'INFERRED', detail: { decided_by: 'size-overhead-model' }, evidence: null },
      enc_alg: field('aes-256-gcm', 'model', 0.883, 'INFERRED'),
      enc_key_len: field(256, 'model', 0.893, 'INFERRED'),
      auth_alg: field('aead', 'model', 0.91, 'INFERRED'),
      pfs: field(true, 'model', 0.997, 'INFERRED'),
      replay: field('unknown', 'none', 0, 'NOT_OBSERVED'),
      lifetime: field('unknown', 'none', 0, 'NOT_OBSERVED'),
    },
    detection: { ipsec_detected: true, evidence: { n_packets: 22, n_esp: 16, n_ah: 0, n_ike: 6 } },
    ai_confidence: 0.89,
    metadata: {
      mean_bytes: { value: 251.3, source: 'measured', confidence: 1 },
      direction_ratio: { value: 0.99, source: 'measured', confidence: 1 },
    },
    assessment: {
      controls: [
        { id: 'child-cipher', rule_version: '1.2.1', title: 'c', status: 'PASS', weight: 25, points: 25, evidence: {}, explanation: 'e', resolve_by: null, remediation: null, source: 'inferred', confidence: 0.883 },
        { id: 'ike-version', rule_version: '1.2.1', title: 'c', status: 'FAIL', weight: 10, points: 2, evidence: {}, explanation: 'e', resolve_by: null, remediation: null, source: 'observed', confidence: 1 },
        { id: 'ike-cipher', rule_version: '1.2.1', title: 'c', status: 'FAIL', weight: 5, points: 1, evidence: {}, explanation: 'e', resolve_by: null, remediation: null, source: 'observed', confidence: 1 },
        { id: 'ike-integrity', rule_version: '1.2.1', title: 'c', status: 'FAIL', weight: 3, points: 1, evidence: {}, explanation: 'e', resolve_by: null, remediation: null, source: 'observed', confidence: 1 },
      ],
      posture_score: 80,
      coverage: 0.6576,
      score_status: 'PUBLISHED',
      security_score: 80,
      risk_score: 20,
      risk_level: 'low',
      risk_band: 'HIGH',
      findings: [
        { id: 'weak-ike-dh', severity: 'critical', likelihood: 3, impact: 5, text: 'IKE SA DH group 2 is weak.', solution: 'ECP.', verdict: 'CONFIRMED' },
        { id: 'weak-ike-cipher', severity: 'high', likelihood: 3, impact: 5, text: 'IKE SA cipher 3des-cbc is weak.', solution: 'AES-GCM.', verdict: 'CONFIRMED' },
        { id: 'weak-ike-integ', severity: 'medium', likelihood: 3, impact: 4, text: 'IKE SA integrity/PRF hmac-sha1 is weak.', solution: 'SHA2+.', verdict: 'CONFIRMED' },
      ],
      threat_matrix: [],
      breakdown: {},
      rule_version: '1.2.1',
    },
  }
}

describe('item 1: gauge track token', () => {
  it('renders the track in the decorative border token, filled arc and label untouched', () => {
    render(<RiskGauge score={20} band="high" delta={null} />)
    const gauge = screen.getByTestId('risk-gauge')
    const svg = gauge.querySelector('svg')
    expect(svg?.innerHTML).toMatch(/text-gauge-track/)
    expect(svg?.innerHTML).not.toMatch(/text-track/)
    expect(svg?.innerHTML).toMatch(/stroke-red/)
  })
})

describe('item 2: Method column completeness', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('every OBSERVED/INFERRED row shows a real method (v21 mapped)', async () => {
    const { InferenceTable } = await import('@/components/inferences/InferenceTable')
    const analysis = mapAnalyzeResponse({ name: 'v21-icmp.pcap' }, v21resp())
    useSentinel.getState().setAnalysis(analysis)
    render(
      <MemoryRouter>
        <InferenceTable analysis={analysis} />
      </MemoryRouter>,
    )
    const table = screen.getByTestId('inference-table')
    const bodyRows = within(table).getAllByRole('row').slice(1)
    expect(bodyRows.length).toBeGreaterThan(10)
    for (const row of bodyRows) {
      const cells = within(row).getAllByRole('cell')
      const value = cells[1]?.textContent ?? ''
      const method = cells[4]?.textContent ?? ''
      if (value !== 'not observed' && !value.includes('not provided')) {
        expect(method, `method for "${cells[0]?.textContent}"`).not.toBe('—')
        expect(method.length, `method for "${cells[0]?.textContent}"`).toBeGreaterThan(0)
      }
    }
    expect(table.textContent).toMatch(/Direct parse/)
    expect(table.textContent).toMatch(/Size-overhead model/)
  })
})

describe('item 3: AI Confidence microcopy', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('subtitle disclaims calibration and caption reads High model confidence', () => {
    const analysis = getFixture('A')
    useSentinel.getState().setAnalysis(analysis)
    render(
      <MemoryRouter>
        <KpiBar analysis={analysis} />
      </MemoryRouter>,
    )
    const card = screen.getByTestId('kpi-confidence')
    expect(card.textContent).toMatch(/Model confidence \(not calibrated\)/)
    expect(card.textContent).not.toMatch(/\(calibrated probability\)/)
    expect(card.textContent).toMatch(/High model confidence/)
    expect(card.textContent).not.toMatch(/Strong estimate/)
  })
})

describe('item 4 (optional): waterfall bars coloured by finding severity', () => {
  it('ike-version bar uses the critical tone, Total stays neutral', async () => {
    const { waterfallBars } = await import('@/components/audit/ScoreWaterfall')
    const controls = [
      { id: 'child-cipher', weight: 25, points: 25, source: 'inferred', confidence: 0.883 },
      { id: 'ike-version', weight: 10, points: 2, source: 'observed', confidence: 1 },
      { id: 'ike-cipher', weight: 5, points: 1, source: 'observed', confidence: 1 },
    ]
    const findings = [
      { id: 'weak-ike-dh', severity: 'critical' },
      { id: 'weak-ike-cipher', severity: 'high' },
    ] as { id: string; severity: 'low' | 'medium' | 'high' | 'critical' }[]
    const bars = waterfallBars(controls, 20, findings)
    const tones: Record<string, string> = Object.fromEntries(bars.map((b) => [b.name, b.tone]))
    expect(tones['ike-version']).toBe('danger')
    expect(tones['ike-cipher']).toBe('orange')
    expect(tones['Total']).toBe('neutral')
    expect(bars.filter((b) => !b.total).reduce((s, b) => s + b.weight, 0)).toBeCloseTo(20, 9)
  })
})
