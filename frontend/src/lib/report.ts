import type { AnalysisResult, Finding, Severity } from '@/types/analysis'
import { dhLabel } from './dh'
import { fmtDuration, fmtPct, fmtInt } from './format'
import { computeRiskScore, riskBand } from './risk'
import { RISK_BAND_LABEL, SEVERITY_LABEL, severityRank } from './severity'
import { THREAT_CATEGORIES, threatMatrix } from './threat'

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low']

const IMPACT: Record<Finding['category'], string> = {
  'Weak Cipher': 'An attacker can recover the encrypted payload offline.',
  'Key Exchange': 'A weak key exchange lets an attacker derive the session keys.',
  PFS: 'Compromise of the long-term key exposes earlier sessions.',
  Replay: 'Recorded packets can be re-injected without detection.',
  Lifetime: 'Long-lived keys widen the window for cryptanalysis and exposure.',
  Metadata: 'Traffic patterns disclose the application and endpoints in use.',
  Protocol: 'The negotiation exposes identities and permits downgrade attacks.',
}

const esc = (value: string | number | null | undefined): string => {
  if (value === null || value === undefined) return '—'
  const text = Array.isArray(value) ? String(value) : String(value)
  if (/undefined|NaN/.test(text)) return '—'
  return text.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')
}

const table = (headers: string[], rows: (string | number)[][]): string => {
  const head = `| ${headers.map(esc).join(' | ')} |`
  const divider = `| ${headers.map(() => '---').join(' | ')} |`
  const body = rows.map((row) => `| ${row.map(esc).join(' | ')} |`).join('\n')
  return [head, divider, body].join('\n')
}

const sortFindings = (findings: Finding[]): Finding[] =>
  [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.ruleId.localeCompare(b.ruleId))

const severitySummary = (findings: Finding[]): string =>
  SEVERITY_ORDER.map((severity) => {
    const count = findings.filter((f) => f.severity === severity).length
    return `${count} ${SEVERITY_LABEL[severity].toLowerCase()}`
  }).join(', ')

export function detectConfidenceBand(confidence: number): 'strong' | 'moderate' | 'weak' {
  if (confidence >= 0.85) return 'strong'
  if (confidence >= 0.7) return 'moderate'
  return 'weak'
}

export function describeConfiguration(analysis: AnalysisResult): string {
  const p = analysis.protocol
  return [
    p.ikeVersion.value,
    `${p.mode.value} mode`,
    `IKE ${p.ike.encryption.value}`,
    `CHILD ${p.child.encryption.value}`,
    dhLabel(p.ike.dhGroup.value),
    analysis.summary.ahPackets > 0 ? 'AH' : 'ESP',
    p.ipVersion.value,
    p.natTraversal.value ? 'NAT-T' : 'no NAT-T',
  ].join(' · ')
}

/** Executive report, about one page (spec 11). */
export function buildExecutiveReport(analysis: AnalysisResult): string {
  const findings = sortFindings(analysis.findings)
  const score = computeRiskScore(findings)
  const band = riskBand(score)
  const confidenceBand = detectConfidenceBand(analysis.overallConfidence)
  const top = findings.slice(0, 3)
  const recommendations = sortFindings(findings)
    .map((f) => f.recommendation)
    .filter((value, index, all) => all.indexOf(value) === index)
    .slice(0, 5)

  const lines: string[] = [
    '# IPsec-AI Sentinel — Executive report',
    '',
    table(
      ['Field', 'Value'],
      [
        ['File', analysis.fileName],
        ['Analysed at', analysis.analyzedAt],
        ['Source', analysis.source === 'live' ? 'Live capture' : 'Uploaded trace'],
        ['Analyst', 'Analyst'],
        ['Capture duration', fmtDuration(analysis.summary.durationSec)],
        ['Packets analysed', fmtInt(analysis.summary.packets)],
      ],
    ),
    '',
    '## Overall risk',
    '',
    `**${score} / 100 — ${RISK_BAND_LABEL[band]}.** ${
      findings.length === 0
        ? 'No rule in the baseline policy failed for this capture.'
        : `The configuration breaches ${findings.length} baseline rule${findings.length === 1 ? '' : 's'} (${severitySummary(findings)}).`
    }`,
    '',
    '## AI confidence',
    '',
    `**${fmtPct(analysis.overallConfidence)}** overall confidence — a ${confidenceBand} estimate. Model confidence over the inferred parameters (rank-ordered, not calibrated), not a measure of accuracy.`,
    '',
    '## Detected configuration',
    '',
    describeConfiguration(analysis),
    '',
    '## Top findings',
    '',
  ]

  if (top.length === 0) {
    lines.push('No findings. This configuration meets the baseline policy.', '')
  } else {
    top.forEach((finding, index) => {
      lines.push(
        `${index + 1}. **${finding.ruleId} — ${finding.title}** (${SEVERITY_LABEL[finding.severity]}). ${IMPACT[finding.category]} Evidence: ${finding.evidence}`,
        '',
      )
    })
  }

  lines.push('## Top recommendations', '')
  if (recommendations.length === 0) {
    lines.push('No remediation is required for this capture.', '')
  } else {
    recommendations.forEach((recommendation, index) => {
      lines.push(`${index + 1}. ${recommendation}`, '')
    })
  }

  lines.push(
    '## Scope and limitations',
    '',
    'Inferred parameters are probabilistic estimates derived from encrypted-traffic side channels; observed parameters are read directly from cleartext protocol fields.',
    '',
    'Demonstration data. Analysis results are simulated.',
    '',
  )

  return lines.join('\n')
}

/** Technical report (spec 11, ten sections plus an appendix). */
export function buildTechnicalReport(analysis: AnalysisResult): string {
  const findings = sortFindings(analysis.findings)
  const score = computeRiskScore(findings)
  const matrix = threatMatrix(findings)
  const p = analysis.protocol
  const confidence = (param: { provenance: string; confidence: number }): string =>
    param.provenance === 'observed' ? 'observed' : `inferred · ${fmtPct(param.confidence)}`

  const lines: string[] = [
    '# IPsec-AI Sentinel — Technical report',
    '',
    `## 1. Summary`,
    '',
    table(
      ['Metric', 'Value'],
      [
        ['File', analysis.fileName],
        ['Analysed at', analysis.analyzedAt],
        ['Source', analysis.source],
        ['Risk score', `${score} / 100 (${RISK_BAND_LABEL[riskBand(score)]})`],
        ['Packets', fmtInt(analysis.summary.packets)],
        ['IKE handshakes', fmtInt(analysis.summary.ikeHandshakes)],
        ['ESP streams', fmtInt(analysis.summary.espStreams)],
        ['AH packets', fmtInt(analysis.summary.ahPackets)],
        ['Duration', fmtDuration(analysis.summary.durationSec)],
        ['Overall confidence', fmtPct(analysis.overallConfidence)],
      ],
    ),
    '',
    '## 2. Detected protocol parameters',
    '',
    table(
      ['Parameter', 'Value', 'Provenance', 'Confidence'],
      [
        ['IKE version', p.ikeVersion.value, 'observed', fmtPct(p.ikeVersion.confidence)],
        ['Exchange mode', p.exchangeMode.value, 'observed', fmtPct(p.exchangeMode.confidence)],
        ['Mode', p.mode.value, 'inferred', fmtPct(p.mode.confidence)],
        ['IP version', p.ipVersion.value, 'observed', fmtPct(p.ipVersion.confidence)],
        ['NAT traversal', p.natTraversal.value ? 'present' : 'absent', 'observed', fmtPct(p.natTraversal.confidence)],
        ['IKE encryption', p.ike.encryption.value, 'observed', fmtPct(p.ike.encryption.confidence)],
        ['IKE integrity', p.ike.integrity.value, 'observed', fmtPct(p.ike.integrity.confidence)],
        ['IKE PRF', p.ike.prf.value, 'observed', fmtPct(p.ike.prf.confidence)],
        ['IKE DH group', dhLabel(p.ike.dhGroup.value), 'observed', fmtPct(p.ike.dhGroup.confidence)],
        ['IKE lifetime', p.ike.lifetimeSec.value === null ? 'not observed' : `${p.ike.lifetimeSec.value} s`, confidence(p.ike.lifetimeSec), fmtPct(p.ike.lifetimeSec.confidence)],
        ['CHILD encryption', p.child.encryption.value, 'inferred', fmtPct(p.child.encryption.confidence)],
        ['CHILD integrity', p.child.integrity.value, 'inferred', fmtPct(p.child.integrity.confidence)],
        ['PFS', p.child.pfs.value ? 'enabled' : 'disabled', 'inferred', fmtPct(p.child.pfs.confidence)],
        ['PFS group', p.child.pfsGroup.value === null ? 'n/a' : dhLabel(p.child.pfsGroup.value), 'inferred', fmtPct(p.child.pfsGroup.confidence)],
        ['CHILD lifetime', p.child.lifetimeSec.value === null ? 'not observed' : `${p.child.lifetimeSec.value} s`, 'inferred', fmtPct(p.child.lifetimeSec.confidence)],
        ['Replay protection', p.child.replayProtection.value ? 'enabled' : 'disabled', 'inferred', fmtPct(p.child.replayProtection.confidence)],
        ['ESN', p.child.esn.value ? 'enabled' : 'disabled', 'inferred', fmtPct(p.child.esn.confidence)],
      ],
    ),
    '',
    '## 3. IKE handshake analysis',
    '',
    table(
      ['#', 'Step', 'Time (s)', 'Direction', 'Size (B)', 'Encrypted'],
      analysis.handshake.map((step) => [
        step.index,
        step.step,
        step.timeSec.toFixed(3),
        step.direction,
        step.sizeBytes,
        step.encrypted ? 'yes' : 'no',
      ]),
    ),
    '',
    '## 4. Security associations',
    '',
    table(
      ['Kind', 'SPI out', 'SPI in', 'Mode', 'Encryption', 'Integrity', 'Packets', 'Bytes', 'Seq range', 'Replay gaps'],
      analysis.sas.map((sa) => [
        sa.kind,
        sa.spiOut,
        sa.spiIn,
        sa.mode,
        sa.encryption,
        sa.integrity,
        fmtInt(sa.packets),
        fmtInt(sa.bytes),
        `${sa.seqMin}–${sa.seqMax}`,
        sa.replayGaps,
      ]),
    ),
    '',
    '## 5. Traffic inference',
    '',
    table(
      ['Class', 'Probability'],
      analysis.trafficClasses.map((entry) => [entry.label, fmtPct(entry.probability)]),
    ),
    '',
    table(
      ['Flow feature', 'Value'],
      [
        ['Mean packet length', `${analysis.flowStats.meanLen} B`],
        ['Std. deviation', analysis.flowStats.stdLen === null ? 'not provided by the analysis API' : `${analysis.flowStats.stdLen} B`],
        ['Mean inter-arrival time', analysis.flowStats.meanIatMs === null ? 'not provided by the analysis API' : `${analysis.flowStats.meanIatMs} ms`],
        ['Burstiness (CV)', analysis.flowStats.burstiness === null ? 'not provided by the analysis API' : String(analysis.flowStats.burstiness)],
        ['Up/down ratio', String(analysis.flowStats.upDownRatio)],
      ],
    ),
    '',
    '## 6. Findings',
    '',
    table(
      ['Rule', 'Severity', 'Category', 'STRIDE', 'Evidence', 'Reference'],
      findings.map((finding) => [
        finding.ruleId,
        SEVERITY_LABEL[finding.severity],
        finding.category,
        finding.stride,
        finding.evidence,
        finding.reference,
      ]),
    ),
    '',
    '## 7. Threat matrix',
    '',
    table(
      ['Severity', ...THREAT_CATEGORIES],
      SEVERITY_ORDER.map((severity) => [
        SEVERITY_LABEL[severity],
        ...THREAT_CATEGORIES.map((category) => matrix[severity][category]),
      ]),
    ),
    '',
    '## 8. Recommendations',
    '',
    ...findings.map((finding) => `- **${finding.ruleId}** — ${finding.recommendation}`),
    findings.length === 0 ? '- No remediation is required for this capture.' : '',
    '',
    '## 9. Methodology',
    '',
    'Findings come from a single rule table evaluated over the detected protocol parameters; rules that depend on an inference below the configured confidence are reported as unknown.',
    '',
    'Risk score = `25 × critical + 12 × high + 5 × medium + 2 × low`, capped at 100.',
    '',
    table(
      ['Model', 'Task', 'Type', 'Version', 'Macro-F1', 'Latency'],
      [
        ['ike-parser-rules', 'IKE/ESP header and proposal parsing', 'Rule-based', '1.4.0', '1.000', '0.4 ms'],
        ['cipher-fingerprint-gbm', 'ESP cipher and integrity family', 'GBM', '2.1.3', '0.962', '3.1 ms'],
        ['mode-pfs-replay-gbm', 'Tunnel/transport, PFS, replay, ESN', 'GBM', '1.8.0', '0.934', '2.7 ms'],
        ['traffic-cnn1d', 'Traffic type inside ESP', 'CNN', '3.0.2', '0.887', '11.8 ms'],
        ['traffic-transformer', 'Traffic type (ensemble member)', 'Transformer', '0.9.1', '0.901', '24.6 ms'],
      ],
    ),
    '',
    '## 10. Limitations and assumptions',
    '',
    '- ESP payloads are encrypted; only cleartext headers and side channels are available.',
    '- Inferred parameters carry model confidence (not calibrated) and may be wrong for atypical traffic.',
    '- The packet list is a representative sample of at most 2,000 rows, not the full capture.',
    '- Demonstration data. Analysis results are simulated.',
    '',
    '## Appendix — provenance legend',
    '',
    '- **Observed** — read directly from cleartext protocol fields.',
    '- **Inferred** — estimated by an AI model from encrypted-traffic characteristics; model confidence is rank-ordered, not calibrated.',
    '',
  ]

  return lines.filter((line) => line !== '').join('\n').replace(/\n{3,}/g, '\n\n')
}
