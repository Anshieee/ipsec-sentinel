/**
 * Backend-mapped UI states (v1.2.1): non-IPsec, ESP-only, WITHHELD,
 * LIKELY and the risk_band floor. Crafted BackendAnalyzeResponse
 * literals (no API needed) through the real mapper.
 */
import { render, screen } from '@testing-library/react'
import { describe, expect, it, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { mapAnalyzeResponse, type BackendAnalyzeResponse } from '@/api/backend'
import { KpiBar } from '@/components/overview/KpiBar'
import { HandshakeTimeline } from '@/components/overview/HandshakeTimeline'
import { FindingsTable } from '@/components/audit/FindingsTable'
import { OverviewPage } from '@/pages/OverviewPage'
import { useSentinel, useDerived } from '@/store/useSentinel'
import type { AnalysisResult } from '@/types/analysis'

function field(value: unknown, source: 'parsed' | 'model' | 'measured' | 'none' = 'parsed', confidence = 1, status: 'OBSERVED' | 'INFERRED' | 'UNKNOWN' | 'NOT_OBSERVED' | 'NOT_APPLICABLE' = 'OBSERVED', evidence: Record<string, unknown> | null = null) {
  return { value, source, confidence, status, detail: null, evidence }
}

function baseResp(overrides: Partial<BackendAnalyzeResponse> = {}): BackendAnalyzeResponse {
  return {
    fields: {},
    ike_sa: {
      version: field('ikev2'),
      enc_alg: field('aes-128-cbc'),
      enc_key_len: field(128),
      auth_alg: field('hmac-sha256'),
      prf: field('hmac-sha256'),
      dh_group: field(14),
    },
    child_sa: {
      proto: field('esp'),
      mode: field('tunnel', 'model', 0.99, 'INFERRED'),
      enc_alg: field('aes-128-cbc', 'model', 0.97, 'INFERRED'),
      enc_key_len: field(128, 'model', 0.97, 'INFERRED'),
      auth_alg: field('hmac-sha256', 'model', 0.99, 'INFERRED'),
      pfs: field(true, 'model', 1, 'INFERRED'),
      replay: field('unknown', 'none', 0, 'NOT_OBSERVED'),
      lifetime: field('unknown', 'none', 0, 'NOT_OBSERVED'),
    },
    detection: { ipsec_detected: true },
    ai_confidence: 0.9,
    metadata: {},
    assessment: {
      controls: [],
      posture_score: 89,
      coverage: 0.6684,
      score_status: 'PUBLISHED',
      security_score: 89,
      risk_score: 11,
      risk_level: 'low',
      risk_band: 'LOW',
      findings: [],
      threat_matrix: [],
      breakdown: {},
      rule_version: '1.2.1',
    },
    ...overrides,
  }
}

function loadMapped(resp: BackendAnalyzeResponse): AnalysisResult {
  const analysis = mapAnalyzeResponse({ name: 't.pcap' }, resp)
  useSentinel.getState().setAnalysis(analysis)
  return analysis
}

describe('non-IPsec state', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('shows one consistent banner and hides gauges, confidence, chips and crypto', () => {
    const analysis = loadMapped(
      baseResp({ detection: { ipsec_detected: false }, assessment: { ...baseResp().assessment, posture_score: null, coverage: 0, score_status: 'WITHHELD', security_score: null, risk_score: null, risk_level: null, risk_band: null } }),
    )
    render(
      <MemoryRouter>
        <OverviewPage />
      </MemoryRouter>,
    )
    expect(screen.getByTestId('no-ipsec-banner')).toBeTruthy()
    expect(screen.getByTestId('kpi-no-ipsec')).toBeTruthy()
    expect(screen.queryByTestId('risk-gauge')).toBeNull()
    expect(screen.queryByTestId('kpi-confidence')).toBeNull()
    expect(screen.queryByTestId('crypto-card')).toBeNull()
    expect(screen.getByTestId('kpi-no-ipsec').textContent).toMatch(/no score/i)
    expect(analysis.riskScore).toBeNull()
  })
})

describe('ESP-only state', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('renders IKE as not observed (never a certain no-IKE) with an empty handshake note', () => {
    const resp = baseResp()
    resp.ike_sa = {
      version: field('unknown', 'none', 0, 'NOT_OBSERVED'),
      enc_alg: field('unknown', 'none', 0, 'NOT_OBSERVED'),
      enc_key_len: field('unknown', 'none', 0, 'NOT_OBSERVED'),
      auth_alg: field('unknown', 'none', 0, 'NOT_OBSERVED'),
      prf: field('unknown', 'none', 0, 'NOT_OBSERVED'),
      dh_group: field('unknown', 'none', 0, 'NOT_OBSERVED'),
    }
    const analysis = loadMapped(resp)
    render(
      <MemoryRouter>
        <KpiBar analysis={analysis} />
      </MemoryRouter>,
    )
    expect(screen.getByText('not observed')).toBeTruthy()
    expect(screen.queryByText('No IKE observed — not applicable.')).toBeNull()
    render(
      <MemoryRouter>
        <HandshakeTimeline steps={analysis.handshake} />
      </MemoryRouter>,
    )
    expect(screen.getAllByText(/No handshake steps reported for this capture/)).toHaveLength(2)
  })
})

describe('WITHHELD state', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('hides the gauge and shows coverage with no risk band', () => {
    const analysis = loadMapped(
      baseResp({ assessment: { ...baseResp().assessment, posture_score: 87, coverage: 0.2012, score_status: 'WITHHELD', security_score: null, risk_score: null, risk_level: null, risk_band: null } }),
    )
    render(
      <MemoryRouter>
        <KpiBar analysis={analysis} />
      </MemoryRouter>,
    )
    expect(screen.getByTestId('kpi-withheld').textContent).toMatch(/20\.1%/)
    expect(screen.queryByTestId('risk-gauge')).toBeNull()
    expect(analysis.riskScore).toBeNull()
  })
})

describe('LIKELY findings', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('badges inferred-evidence findings without touching CONFIRMED ones', () => {
    const analysis = loadMapped(
      baseResp({
        assessment: {
          ...baseResp().assessment,
          findings: [
            { id: 'weak-cipher', severity: 'high', likelihood: 3, impact: 5, text: 'Likely: 3des…', solution: 'AES-GCM.', verdict: 'LIKELY' },
          ],
        },
      }),
    )
    render(
      <MemoryRouter>
        <FindingsTable findings={analysis.findings} selection={null} />
      </MemoryRouter>,
    )
    expect(screen.getByText('LIKELY')).toBeTruthy()
    expect(analysis.findings[0]?.verdict).toBe('LIKELY')
  })
})

describe('v21 risk band', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
  })

  it('reads HIGH from the backend (never recomputed client-side)', () => {
    const analysis = loadMapped(
      baseResp({
        assessment: {
          ...baseResp().assessment,
          posture_score: 80,
          coverage: 0.6576,
          security_score: 80,
          risk_score: 20,
          risk_level: 'low',
          risk_band: 'HIGH',
          findings: [
            { id: 'weak-ike-dh', severity: 'critical', likelihood: 3, impact: 5, text: 'IKE SA DH group 2…', solution: 'ECP.', verdict: 'CONFIRMED' },
          ],
        },
      }),
    )
    const { result } = (() => {
      let value: ReturnType<typeof useDerived> | null = null
      const Probe = () => {
        value = useDerived()
        return null
      }
      render(
        <MemoryRouter>
          <Probe />
        </MemoryRouter>,
      )
      return { result: value as unknown as ReturnType<typeof useDerived> }
    })()
    expect(result.band).toBe('high')
    expect(result.riskScore).toBe(20)
    render(
      <MemoryRouter>
        <KpiBar analysis={analysis} />
      </MemoryRouter>,
    )
    const gauge = screen.getByTestId('risk-gauge')
    expect(gauge).toHaveAttribute('aria-valuenow', '20')
  })
})
