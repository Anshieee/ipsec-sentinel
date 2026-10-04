/**
 * v1.2.3 Part A honesty tests (test-first): crafted backend-shaped
 * responses through the real mapper, no API needed.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { mapAnalyzeResponse, type BackendAnalyzeResponse } from '@/api/backend'
import { waterfallBars } from '@/components/audit/ScoreWaterfall'
import { AuditSummary } from '@/components/audit/AuditSummary'
import { CategoryBars } from '@/components/audit/CategoryBars'
import { CompliancePage } from '@/pages/CompliancePage'
import { UploadZone } from '@/components/overview/UploadZone'
import { useSentinel } from '@/store/useSentinel'
import type { AnalysisResult } from '@/types/analysis'

type Status = 'OBSERVED' | 'INFERRED' | 'UNKNOWN' | 'NOT_OBSERVED' | 'NOT_APPLICABLE'
function field(value: unknown, source: 'parsed' | 'model' | 'measured' | 'none' = 'parsed', confidence = 1, status: Status = 'OBSERVED', evidence: Record<string, unknown> | null = null) {
  return { value, source, confidence, status, detail: null, evidence }
}

function v21ike() {
  return {
    version: field('ikev2', 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
    enc_alg: field('3des-cbc', 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
    enc_key_len: field(168, 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
    auth_alg: field('hmac-sha1', 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
    prf: field('hmac-sha1', 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
    dh_group: field(2, 'parsed', 1, 'OBSERVED', { exchange: 'ike-sa-init', role: 'responder-selected', packet: 2 }),
  }
}

function v21child() {
  return {
    proto: field('esp'),
    mode: field('tunnel', 'model', 0.99, 'INFERRED'),
    enc_alg: field('aes-256-gcm', 'model', 0.883, 'INFERRED'),
    enc_key_len: field(256, 'model', 0.893, 'INFERRED'),
    auth_alg: field('aead', 'model', 0.91, 'INFERRED'),
    pfs: field(true, 'model', 0.997, 'INFERRED'),
    replay: field('unknown', 'none', 0, 'NOT_OBSERVED'),
    lifetime: field('unknown', 'none', 0, 'NOT_OBSERVED'),
  }
}

function v21controls() {
  const c = (id: string, status: string, points: number, weight: number, source: string, confidence: number, extra: Record<string, unknown> = {}) => ({
    id, rule_version: '1.2.1', title: id, status, weight, points,
    evidence: { field: id }, explanation: `${id} explanation`, resolve_by: null, remediation: null,
    source, confidence, ...extra,
  })
  return [
    c('child-cipher', 'PASS', 25, 25, 'inferred', 0.883),
    c('dh-strength', 'UNKNOWN', 0, 20, 'none', 0, { resolve_by: 'Capture IKE_SA_INIT carrying the group.' }),
    c('integrity', 'PASS', 15, 15, 'inferred', 0.91),
    c('pfs', 'PASS', 10, 10, 'inferred', 0.997),
    c('lifetime', 'UNKNOWN', 0, 10, 'none', 0, { resolve_by: 'Provide rekey intervals.' }),
    c('replay', 'UNKNOWN', 0, 5, 'none', 0, { resolve_by: 'Read receiver configuration.' }),
    c('ike-version', 'FAIL', 2, 10, 'observed', 1),
    c('ike-cipher', 'FAIL', 1, 5, 'observed', 1),
    c('ike-integrity', 'FAIL', 1, 3, 'observed', 1),
    c('mode-exposure', 'PASS', 5, 5, 'inferred', 0.99),
  ]
}

function v21resp(): BackendAnalyzeResponse {
  return {
    fields: {
      traffic_type: field('icmp', 'model', 0.9967, 'INFERRED'),
      ip_version: field(4, 'parsed', 1, 'OBSERVED'),
      nat_t: field(false, 'parsed', 1, 'OBSERVED'),
    },
    ike_sa: v21ike(),
    child_sa: v21child(),
    detection: { ipsec_detected: true, evidence: { n_packets: 22, n_esp: 16, n_ah: 0, n_ike: 6 } },
    ai_confidence: 0.89,
    metadata: {
      mean_bytes: { value: 251.3, source: 'measured', confidence: 1 },
      direction_ratio: { value: 0.99, source: 'measured', confidence: 1 },
    },
    assessment: {
      controls: v21controls(),
      posture_score: 80,
      coverage: 0.6356,
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

function loadMapped(resp: BackendAnalyzeResponse): AnalysisResult {
  const analysis = mapAnalyzeResponse({ name: 'v21-icmp.pcap' }, resp)
  useSentinel.getState().setAnalysis(analysis)
  return analysis
}

describe('item 1: headline band', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('shows Risk 20 → HIGH raised by the confirmed critical, never a lone low', () => {
    loadMapped(v21resp())
    render(
      <MemoryRouter>
        <AuditSummary />
      </MemoryRouter>,
    )
    const el = screen.getByTestId('backend-assessment')
    expect(el.textContent).toMatch(/Risk 20 → HIGH/)
    expect(el.textContent).toMatch(/raised by confirmed critical/i)
    expect(el.textContent).not.toMatch(/\(low\)/)
  })
})

describe('item 2: waterfall bars sum to risk', () => {
  it('bars from backend controls sum exactly to the displayed total', () => {
    const controls = [
      { id: 'child-cipher', weight: 25, points: 25, source: 'inferred', confidence: 0.883 },
      { id: 'ike-version', weight: 10, points: 2, source: 'observed', confidence: 1 },
      { id: 'ike-cipher', weight: 5, points: 1, source: 'observed', confidence: 1 },
      { id: 'ike-integrity', weight: 3, points: 1, source: 'observed', confidence: 1 },
      { id: 'dh-strength', weight: 20, points: 0, source: 'none', confidence: 0 },
    ]
    const bars = waterfallBars(controls, 20)
    const parts = bars.filter((b) => !b.total)
    expect(parts.length).toBe(3)
    expect(parts.reduce((s, b) => s + b.weight, 0)).toBeCloseTo(20, 9)
    expect(bars.find((b) => b.total)?.weight).toBe(20)
  })
})

describe('item 3: categories never plot unknown as safe', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('labels unevaluated categories instead of maxing them', () => {
    const analysis = loadMapped(v21resp())
    render(
      <MemoryRouter>
        <CategoryBars analysis={analysis} />
      </MemoryRouter>,
    )
    const el = screen.getByTestId('category-bars')
    expect(el.textContent).toMatch(/not evaluated/i)
    expect(el.textContent).toMatch(/Lifetime/)
    // evaluated categories still render with their state
    expect(el.textContent).toMatch(/Key Exchange/)
  })
})

describe('item 4: compliance rows carry version and resolve-by', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('shows rule version on every row and resolve text on UNKNOWN rows (v21)', () => {
    loadMapped(v21resp())
    render(
      <MemoryRouter>
        <CompliancePage />
      </MemoryRouter>,
    )
    const table = screen.getByTestId('controls-table')
    expect(table.textContent).toMatch(/1\.2\.1/)
    expect(table.textContent).toMatch(/Capture IKE_SA_INIT carrying the group/)
    expect(table.textContent).toMatch(/Provide rekey intervals/)
  })
})

describe('item 5: upload summary uses evidence counts', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('shows IKE 6 / ESP 16 from detection.evidence, not 1 / 1', () => {
    const analysis = loadMapped(v21resp())
    useSentinel.setState({
      upload: { status: 'complete', progress: 100, fileName: 'v21-icmp.pcap', summary: analysis.summary },
    })
    render(
      <MemoryRouter>
        <UploadZone />
      </MemoryRouter>,
    )
    const box = screen.getByTestId('upload-complete')
    expect(box.textContent).toMatch(/22/)
    expect(box.textContent).toMatch(/6/)
    expect(box.textContent).toMatch(/16/)
  })
})

describe('item 6: ip_version and nat_t map with real status', () => {
  it('maps OBSERVED fields with backend confidence, absent keys as not provided', () => {
    const analysis = mapAnalyzeResponse({ name: 'v21-icmp.pcap' }, v21resp())
    expect(analysis.protocol.ipVersion.value).toBe('IPv4')
    expect(analysis.protocol.ipVersion.status).toBe('OBSERVED')
    expect(analysis.protocol.ipVersion.confidence).toBe(1)
    expect(analysis.protocol.natTraversal.value).toBe(false)
    expect(analysis.protocol.natTraversal.status).toBe('OBSERVED')
    const bare = mapAnalyzeResponse(
      { name: 'old.pcap' },
      { ...v21resp(), ike_sa: {}, child_sa: { proto: field('esp') }, fields: {} },
    )
    expect(bare.protocol.ipVersion.note).toMatch(/not provided by the analysis API/i)
  })
})

describe('item 7: flow features show values only when provided', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('renders not-provided text instead of 0.00 defaults', async () => {
    const { FlowFeaturesCard } = await import('@/components/inferences/FlowFeaturesCard')
    const analysis = loadMapped(v21resp())
    render(<FlowFeaturesCard analysis={analysis} />)
    const card = screen.getByTestId('flow-features')
    expect(card.textContent).toMatch(/not provided by the analysis API/i)
    expect(card.textContent).not.toMatch(/0\.00/)
  })
})

describe('item 8: accuracy table marks deliberately-unpredicted fields', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
    useSentinel.setState({ settings: { ...useSentinel.getState().settings, dataSource: 'live' } })
  })

  it('renders dh_group as not predicted, not 0.0%', async () => {
    const { ModelEvaluation } = await import('@/components/inferences/ModelEvaluation')
    render(
      <MemoryRouter>
        <ModelEvaluation />
      </MemoryRouter>,
    )
    const card = screen.getByTestId('eval-accuracy')
    expect(card.textContent).toMatch(/not predicted \(read from the handshake\)/i)
    const rows = screen.getAllByRole('row')
    const dhRow = rows.find((r) => r.textContent?.includes('dh_group'))
    expect(dhRow?.textContent).toMatch(/not predicted/)
    expect(dhRow?.textContent).not.toMatch(/0\.0%/)
  })
})
