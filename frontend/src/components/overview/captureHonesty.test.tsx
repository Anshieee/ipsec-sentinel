/**
 * v1.2.4 Part A honesty tests (test-first): voip-shaped backend data
 * (22 packets: 6 IKE / 400→16 ESP evidence, 3DES/SHA1/DH2 IKE, HIGH band)
 * through the real mapper; no API needed.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { mapAnalyzeResponse, type BackendAnalyzeResponse } from '@/api/backend'
import { CategoryBars } from '@/components/audit/CategoryBars'
import { KpiBar } from '@/components/overview/KpiBar'
import { StatusChipsRow } from '@/components/overview/StatusChipsRow'
import { useSentinel } from '@/store/useSentinel'
import type { AnalysisResult } from '@/types/analysis'

type Status = 'OBSERVED' | 'INFERRED' | 'UNKNOWN' | 'NOT_OBSERVED' | 'NOT_APPLICABLE'
function field(value: unknown, source: 'parsed' | 'model' | 'measured' | 'none' = 'parsed', confidence = 1, status: Status = 'OBSERVED', evidence: Record<string, unknown> | null = null) {
  return { value, source, confidence, status, detail: null, evidence }
}

function voipControls() {
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

function voipResp(): BackendAnalyzeResponse {
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
      mode: field('tunnel', 'model', 0.99, 'INFERRED'),
      enc_alg: field('aes-256-gcm', 'model', 0.883, 'INFERRED'),
      enc_key_len: field(256, 'model', 0.893, 'INFERRED'),
      auth_alg: field('aead', 'model', 0.91, 'INFERRED'),
      pfs: field(true, 'model', 0.997, 'INFERRED'),
      replay: field('unknown', 'none', 0, 'NOT_OBSERVED'),
      lifetime: field('unknown', 'none', 0, 'NOT_OBSERVED'),
    },
    detection: { ipsec_detected: true, evidence: { n_packets: 406, n_esp: 400, n_ah: 0, n_ike: 6 } },
    ai_confidence: 0.89,
    metadata: {
      mean_bytes: { value: 251.3, source: 'measured', confidence: 1 },
      direction_ratio: { value: 0.99, source: 'measured', confidence: 1 },
    },
    assessment: {
      controls: voipControls(),
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

function loadMapped(resp: BackendAnalyzeResponse): AnalysisResult {
  const analysis = mapAnalyzeResponse({ name: 'v21-voip.pcap' }, resp)
  useSentinel.getState().setAnalysis(analysis)
  return analysis
}

describe('item 1: capture volume labels packet counts honestly', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('voip shows IKE packets 6 / ESP packets 400, never handshakes 6', () => {
    const analysis = loadMapped(voipResp())
    expect(analysis.summary.ikeHandshakes).toBe(6)
    expect(analysis.summary.espStreams).toBe(400)
    render(
      <MemoryRouter>
        <KpiBar analysis={analysis} />
      </MemoryRouter>,
    )
    const volume = screen.getByTestId('kpi-volume')
    expect(volume.textContent).toMatch(/IKE packets/)
    expect(volume.textContent).toMatch(/ESP packets/)
    expect(volume.textContent).not.toMatch(/handshakes 6/i)
    expect(volume.textContent).not.toMatch(/streams 1\b/)
  })
})

describe('item 2: status chips driven by backend status', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('voip replay/lifetimes render neutral not-observed chips, no policy text', () => {
    const analysis = loadMapped(voipResp())
    render(
      <MemoryRouter>
        <StatusChipsRow analysis={analysis} />
      </MemoryRouter>,
    )
    const row = screen.getByTestId('status-chips')
    expect(row.textContent).toMatch(/not observed/i)
    expect(row.textContent).not.toMatch(/Within policy/)
    expect(row.textContent).not.toMatch(/Threshold/)
  })

  it('ESP-only lifetimes render neutral without red x or green check', () => {
    const resp = voipResp()
    resp.child_sa = { ...resp.child_sa, pfs: field('unknown', 'none', 0, 'UNKNOWN') }
    const analysis = loadMapped(resp)
    const { container } = render(
      <MemoryRouter>
        <StatusChipsRow analysis={analysis} />
      </MemoryRouter>,
    )
    expect(container.querySelectorAll('svg').length).toBe(0)
  })
})

describe('item 3: categories from findings first', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('Key Exchange reads At risk for confirmed weak-ike-dh; no finding category is Safe', () => {
    const analysis = loadMapped(voipResp())
    render(
      <MemoryRouter>
        <CategoryBars analysis={analysis} />
      </MemoryRouter>,
    )
    expect(screen.getByTestId('category-row-key-exchange').textContent).toMatch(/At risk/)
    for (const f of analysis.findings) {
      const slug = f.category.toLowerCase().replace(/[^a-z0-9]+/g, '-')
      const row = screen.getByTestId(`category-row-${slug}`)
      expect(row.textContent).not.toMatch(/Not evaluated/)
      expect(row.textContent).not.toMatch(/Safe/)
    }
  })

  it('inferred PASS reads Pass (inferred), unevaluated reads Not evaluated', () => {
    const analysis = loadMapped(voipResp())
    render(
      <MemoryRouter>
        <CategoryBars analysis={analysis} />
      </MemoryRouter>,
    )
    // PFS category: pfs PASS inferred -> Pass (inferred), never Safe
    expect(screen.getByTestId('category-row-pfs').textContent).toMatch(/Pass \(inferred\)/)
    expect(screen.getByTestId('category-row-lifetime').textContent).toMatch(/Not evaluated/)
    expect(screen.getByTestId('category-row-replay').textContent).toMatch(/Not evaluated/)
  })
})

describe('item 4: waterfall labels one decimal with headroom', () => {
  it('labels read 11.4/5.7/2.9/Total 20.0 and sum to the total', async () => {
    const { waterfallBars } = await import('@/components/audit/ScoreWaterfall')
    const bars = waterfallBars(voipControls(), 20)
    const parts = bars.filter((b) => !b.total)
    expect(parts.reduce((s, b) => s + b.weight, 0)).toBeCloseTo(20, 9)
    const labels = parts.map((b) => b.weight.toFixed(1))
    expect(labels).toContain('11.4')
    expect(labels).toContain('5.7')
    expect(labels).toContain('2.9')
  })
})
