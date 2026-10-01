import { describe, expect, it } from 'vitest'
import { FIXTURE_SPECS } from './spec'
import { buildFixture } from './fixtureBuilder'
import { getFixture, cloneFixture, getFixtureForFileName } from './index'
import { TRAFFIC_LABELS, confusionMatrix, reliabilityDiagram } from '../modelEval'
import { nextLogs, logsFrom, logAt } from '../logs'
import { MODEL_REGISTRY } from '../models'

const IDS = ['A', 'B', 'C'] as const
const EXPECTED_SCORES: Record<string, number> = { A: 9, B: 78, C: 94 }

describe('fixtures', () => {
  it.each(IDS)('fixture %s scores exactly %s', (id) => {
    const fixture = getFixture(id)
    expect(fixture.riskScore).toBe(EXPECTED_SCORES[id])
    expect(fixture.findings.length).toBeGreaterThan(0)
  })

  it.each(IDS)('fixture %s has probabilities summing to 1', (id) => {
    const fixture = getFixture(id)
    const total = fixture.trafficClasses.reduce((sum, c) => sum + c.probability, 0)
    expect(total).toBeCloseTo(1, 6)
    const labels = fixture.trafficClasses.map((c) => c.label)
    expect(new Set(labels).size).toBe(TRAFFIC_LABELS.length)
  })

  it.each(IDS)('fixture %s SA packet totals are within 1 %% of the summary', (id) => {
    const fixture = getFixture(id)
    const total = fixture.sas.reduce((sum, sa) => sum + sa.packets, 0)
    const expected = fixture.summary.packets * 0.99
    expect(Math.abs(total - expected) / fixture.summary.packets).toBeLessThanOrEqual(0.01)
  })

  it.each(IDS)('fixture %s is deterministic across two builds', (id) => {
    const first = buildFixture(FIXTURE_SPECS[id])
    const second = buildFixture(FIXTURE_SPECS[id])
    expect(JSON.stringify(first)).toEqual(JSON.stringify(second))
  })

  it.each(IDS)('fixture %s sample is sorted, capped and starts with the handshake', (id) => {
    const fixture = getFixture(id)
    expect(fixture.packets.length).toBeLessThanOrEqual(2000)
    expect(fixture.packets.length).toBeGreaterThan(0)
    for (let i = 1; i < fixture.packets.length; i++) {
      const previous = fixture.packets[i - 1]
      const current = fixture.packets[i]
      if (!previous || !current) continue
      expect(current.timeSec).toBeGreaterThanOrEqual(previous.timeSec)
      expect(current.no).toBe(i + 1)
    }
    expect(fixture.packets[0]?.proto).toBe('IKE')
  })

  it('fixture A handshake has IKE_SA_INIT, IKE_AUTH, ESP and one rekey pair', () => {
    const fixture = getFixture('A')
    const steps = fixture.handshake.map((s) => s.step)
    expect(steps.filter((s) => s.startsWith('IKE_SA_INIT'))).toHaveLength(2)
    expect(steps.filter((s) => s.startsWith('IKE_AUTH'))).toHaveLength(2)
    expect(steps.filter((s) => s.startsWith('CREATE_CHILD_SA'))).toHaveLength(2)
    expect(steps).toContain('ESP stream established')
    const init = fixture.handshake[0]
    expect(init?.sizeBytes).toBe(184 + 256) // group 14 KE payload
    expect(init?.details['Initiator SPI']).toMatch(/^[0-9a-f]{16}$/)
  })

  it('fixture B has two rekeys and a NAT-T IKE port', () => {
    const fixture = getFixture('B')
    expect(fixture.handshake.filter((s) => s.step.startsWith('CREATE_CHILD_SA'))).toHaveLength(4)
    expect(fixture.protocol.natTraversal.value).toBe(true)
    const rekeyTimes = fixture.handshake.filter((s) => s.step.startsWith('CREATE_CHILD_SA')).map((s) => s.timeSec)
    expect(rekeyTimes[0]).toBeCloseTo(32400, 6)
    expect(rekeyTimes[1]).toBeCloseTo(32400.02, 6)
    expect(rekeyTimes[2]).toBeCloseTo(64800, 6)
    expect(rekeyTimes[3]).toBeCloseTo(64800.02, 6)
  })

  it('fixture C uses IKEv1 steps, IPv6 endpoints and marks Quick Mode encrypted', () => {
    const fixture = getFixture('C')
    expect(fixture.handshake[0]?.step).toBe('Phase 1 Aggressive Mode msg 1')
    expect(fixture.handshake[3]?.encrypted).toBe(true)
    expect(fixture.packets[0]?.src).toContain(':')
    expect(fixture.summary.packets).toBe(9377)
  })

  it('reports replay gaps as specified', () => {
    expect(getFixture('A').sas.reduce((s, sa) => s + sa.replayGaps, 0)).toBe(0)
    expect(getFixture('B').sas.reduce((s, sa) => s + sa.replayGaps, 0)).toBe(3)
    expect(getFixture('C').sas.reduce((s, sa) => s + sa.replayGaps, 0)).toBe(0)
  })

  it('keeps derived statistics finite and shaped correctly', () => {
    for (const id of IDS) {
      const fixture = getFixture(id)
      expect(fixture.lengthHistogram).toHaveLength(12)
      expect(fixture.lengthHistogram.reduce((s, b) => s + b.count, 0)).toBeGreaterThan(0)
      expect(fixture.timeSeries.length).toBe(Math.ceil(fixture.summary.durationSec / 10))
      expect(Number.isFinite(fixture.flowStats.meanLen)).toBe(true)
      expect(fixture.flowStats.meanIatMs).toBeGreaterThan(0)
      expect(fixture.featureEvidence).toHaveLength(5)
      for (const entry of fixture.featureEvidence) {
        expect(entry.features).toHaveLength(4)
        const sum = entry.features.reduce((s, f) => s + f.weight, 0)
        expect(sum).toBeCloseTo(1, 6)
        for (let i = 1; i < entry.features.length; i++) {
          const previous = entry.features[i - 1]
          const current = entry.features[i]
          if (previous && current) expect(previous.weight).toBeGreaterThanOrEqual(current.weight)
        }
      }
      expect(fixture.overallConfidence).toBeGreaterThan(0)
      expect(fixture.handshake.length).toBeGreaterThan(3)
    }
  })

  it('derives provenance for every protocol parameter', () => {
    const fixture = getFixture('A')
    const p = fixture.protocol
    expect(p.ikeVersion.provenance).toBe('observed')
    expect(p.ikeVersion.confidence).toBe(1)
    expect(p.child.encryption.provenance).toBe('inferred')
    expect(p.child.encryption.confidence).toBeCloseTo(0.97, 6)
    expect(p.mode.value).toBe('tunnel')
    expect(p.ike.dhGroup.value).toBe(14)
  })
})

describe('fixture selection', () => {
  it('selects by file name keywords', () => {
    expect(getFixtureForFileName('office_gcm_capture.pcapng').id).toBe('fixture-A')
    expect(getFixtureForFileName('branch_cbc_trace.pcap').id).toBe('fixture-B')
    expect(getFixtureForFileName('legacy_ikev1.pcap').id).toBe('fixture-C')
    expect(getFixtureForFileName('ikev1_branch.pcap').id).toBe('fixture-C')
  })

  it('clones detach from the cached instance', () => {
    const clone = cloneFixture('A')
    clone.riskScore = 99
    expect(getFixture('A').riskScore).toBe(9)
  })
})

describe('model evaluation data', () => {
  it('produces a confusion matrix whose rows sum to 1', () => {
    const matrix = confusionMatrix()
    expect(matrix.labels).toHaveLength(7)
    expect(matrix.rows).toHaveLength(7)
    matrix.rows.forEach((row) => {
      expect(row).toHaveLength(7)
      expect(row.reduce((s, v) => s + v, 0)).toBeCloseTo(1, 6)
    })
    matrix.rows.forEach((row, i) => {
      expect(row[i]).toBeGreaterThanOrEqual(0.82)
      expect(row[i]).toBeLessThanOrEqual(0.97)
    })
    const second = confusionMatrix()
    expect(second).toEqual(matrix)
  })

  it('produces a reliability curve slightly below the diagonal at high confidence', () => {
    const points = reliabilityDiagram()
    expect(points).toHaveLength(10)
    expect(points[0]?.predicted).toBe(0.1)
    expect(points[9]?.predicted).toBe(1.0)
    expect(points[9]?.observed).toBeLessThan(points[9].predicted)
    expect(reliabilityDiagram()).toEqual(points)
  })
})

describe('model registry and logs', () => {
  it('exposes five models with the specified metrics', () => {
    expect(MODEL_REGISTRY).toHaveLength(5)
    expect(MODEL_REGISTRY[0]?.macroF1).toBe(1)
    expect(MODEL_REGISTRY[4]?.name).toBe('traffic-transformer')
    expect(MODEL_REGISTRY[4]?.latencyMs).toBe(24.6)
  })

  it('returns the initial 200 log lines and then one line per request', () => {
    const initial = nextLogs()
    expect(initial).toHaveLength(200)
    expect(initial[0]?.id).toBe('log-0')
    const next = nextLogs('log-199')
    expect(next).toHaveLength(1)
    expect(next[0]?.id).toBe('log-200')
    expect(next[0]?.ts).toBe(logAt(200).ts)
  })

  it('is deterministic and never repeats an id', () => {
    const lines = logsFrom(10, 50)
    expect(lines).toEqual(logsFrom(10, 50))
    expect(new Set(lines.map((l) => l.id)).size).toBe(50)
    for (const line of lines) {
      expect(['DEBUG', 'INFO', 'WARN', 'ERROR']).toContain(line.level)
      expect(line.message.length).toBeGreaterThan(0)
    }
  })
})
