import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { ConfidenceBar } from '@/components/ui/ConfidenceBar'
import { ProvenanceBadge } from '@/components/ui/ProvenanceBadge'
import { useSentinel } from '@/store/useSentinel'
import { dhLabel } from '@/lib/dh'
import { fmtPct } from '@/lib/format'
import { setHighlightAndNavigate } from '@/lib/highlight'
import type { AnalysisResult, Finding, Param } from '@/types/analysis'

type Method = 'Direct parse' | 'Rule-based heuristic' | 'GBM classifier' | 'Sequence model'

interface ParamRow {
  key: string
  label: string
  display: string
  param: Param<unknown>
  method: Method
  rules: string[]
}

const PARAM_RULES: Record<string, string[]> = {
  dhGroup: ['R01', 'R11'],
  ikeEncryption: ['R02', 'R08'],
  childEncryption: ['R02', 'R08'],
  ikeIntegrity: ['R07'],
  childIntegrity: ['R07'],
  pfs: ['R04'],
  replay: ['R05'],
  lifetime: ['R06'],
  esn: ['R10'],
  traffic: ['R09'],
}

function buildRows(analysis: AnalysisResult): ParamRow[] {
  const p = analysis.protocol
  const raw: ParamRow[] = [
    { key: 'ikeVersion', label: 'IKE version', display: p.ikeVersion.value, param: p.ikeVersion, method: 'Direct parse', rules: [] },
    { key: 'exchangeMode', label: 'Exchange mode', display: p.exchangeMode.value, param: p.exchangeMode, method: 'Direct parse', rules: [] },
    { key: 'mode', label: 'Tunnel / transport', display: p.mode.value, param: p.mode, method: 'Direct parse', rules: [] },
    { key: 'ipVersion', label: 'IP version', display: p.ipVersion.value, param: p.ipVersion, method: 'Direct parse', rules: [] },
    { key: 'natTraversal', label: 'NAT traversal', display: p.natTraversal.value ? 'Detected' : 'Not detected', param: p.natTraversal, method: 'Direct parse', rules: [] },
    { key: 'ikeEncryption', label: 'IKE cipher', display: p.ike.encryption.value, param: p.ike.encryption, method: p.ike.encryption.provenance === 'observed' ? 'Direct parse' : 'GBM classifier', rules: PARAM_RULES.ikeEncryption ?? [] },
    { key: 'ikeIntegrity', label: 'IKE integrity', display: p.ike.integrity.value, param: p.ike.integrity, method: p.ike.integrity.provenance === 'observed' ? 'Direct parse' : 'GBM classifier', rules: PARAM_RULES.ikeIntegrity ?? [] },
    { key: 'prf', label: 'PRF', display: p.ike.prf.value, param: p.ike.prf, method: 'Rule-based heuristic', rules: [] },
    { key: 'dhGroup', label: 'DH group', display: dhLabel(p.ike.dhGroup.value), param: p.ike.dhGroup, method: p.ike.dhGroup.provenance === 'observed' ? 'Direct parse' : 'Rule-based heuristic', rules: PARAM_RULES.dhGroup ?? [] },
    { key: 'childEncryption', label: 'CHILD cipher', display: p.child.encryption.value, param: p.child.encryption, method: p.child.encryption.provenance === 'observed' ? 'Direct parse' : 'GBM classifier', rules: PARAM_RULES.childEncryption ?? [] },
    { key: 'childIntegrity', label: 'CHILD integrity', display: p.child.integrity.value, param: p.child.integrity, method: p.child.integrity.provenance === 'observed' ? 'Direct parse' : 'GBM classifier', rules: PARAM_RULES.childIntegrity ?? [] },
    { key: 'pfs', label: 'PFS', display: p.child.pfs.value ? 'Enabled' : 'Disabled', param: p.child.pfs, method: p.child.pfs.provenance === 'observed' ? 'Direct parse' : 'GBM classifier', rules: PARAM_RULES.pfs ?? [] },
    { key: 'pfsGroup', label: 'PFS group', display: p.child.pfsGroup.value === null ? '—' : dhLabel(p.child.pfsGroup.value), param: { value: p.child.pfsGroup.value, provenance: p.child.pfs.provenance, confidence: p.child.pfs.confidence }, method: 'Rule-based heuristic', rules: [] },
    { key: 'lifetime', label: 'CHILD lifetime', display: p.child.lifetimeSec.value === null ? '—' : `${p.child.lifetimeSec.value} s`, param: p.child.lifetimeSec, method: p.child.lifetimeSec.provenance === 'observed' ? 'Direct parse' : 'GBM classifier', rules: PARAM_RULES.lifetime ?? [] },
    { key: 'replay', label: 'Replay protection', display: p.child.replayProtection.value ? 'Enabled' : 'Disabled', param: p.child.replayProtection, method: p.child.replayProtection.provenance === 'observed' ? 'Direct parse' : 'GBM classifier', rules: PARAM_RULES.replay ?? [] },
    { key: 'esn', label: 'ESN', display: p.child.esn.value ? 'Enabled' : 'Disabled', param: p.child.esn, method: p.child.esn.provenance === 'observed' ? 'Direct parse' : 'GBM classifier', rules: PARAM_RULES.esn ?? [] },
  ]
  return raw
}

/** Inference table with per-parameter evidence expansion (spec 10.3 item 1). */
export function InferenceTable({ analysis }: { analysis: AnalysisResult }) {
  const minRuleConfidence = useSentinel((s) => s.settings.minRuleConfidence)
  const [expanded, setExpanded] = useState<string | null>(null)
  const rows = useMemo(() => buildRows(analysis), [analysis])

  const relatedFindings = (row: ParamRow): Finding[] =>
    analysis.findings.filter((finding) => row.rules.includes(finding.ruleId))

  return (
    <Card data-testid="inference-table">
      <CardHeader
        title="Detected protocol parameters"
        description={`${rows.length} parameters · confidence below ${fmtPct(minRuleConfidence)} is treated as unknown by the rule engine`}
      />
      <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Inference table">
        <table className="w-full border-collapse text-xs">
          <caption className="sr-only">Inferred and observed protocol parameters with confidence</caption>
          <thead>
            <tr className="bg-raised text-left text-muted">
              <th scope="col" className="px-3 py-2 font-medium">Parameter</th>
              <th scope="col" className="px-3 py-2 font-medium">Value</th>
              <th scope="col" className="px-3 py-2 font-medium">Provenance</th>
              <th scope="col" className="px-3 py-2 font-medium">Confidence</th>
              <th scope="col" className="px-3 py-2 font-medium">Method</th>
              <th scope="col" className="px-3 py-2 font-medium">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const open = expanded === row.key
              const related = relatedFindings(row)
              return [
                <tr key={row.key} className="border-t border-line/60 align-top">
                  <td className="px-3 py-2 text-ink">{row.label}</td>
                  <td className="px-3 py-2 text-ink">
                    <span className="break-all">{row.display}</span>
                    {related.length > 0 ? (
                      <Link
                        to="/audit"
                        onClick={() => setHighlightAndNavigate(related[0]?.id ?? '')}
                        className="ml-1.5 inline-flex align-middle"
                      >
                        <Badge tone="danger">Finding {related[0]?.ruleId}</Badge>
                        <span className="sr-only">Related finding on the audit page</span>
                      </Link>
                    ) : null}
                  </td>
                  <td className="px-3 py-2">
                    <ProvenanceBadge provenance={row.param.provenance} />
                  </td>
                  <td className="px-3 py-2">
                    <ConfidenceBar value={row.param.confidence} ariaLabel={`${row.label} confidence`} />
                  </td>
                  <td className="px-3 py-2 text-muted">{row.method}</td>
                  <td className="px-3 py-2">
                    <button
                      type="button"
                      aria-expanded={open}
                      data-testid={`expand-${row.key}`}
                      onClick={() => setExpanded(open ? null : row.key)}
                      className="inline-flex items-center gap-1 rounded-control px-1.5 py-1 text-[11px] text-accent hover:bg-raised"
                    >
                      {open ? <ChevronDown size={12} aria-hidden="true" /> : <ChevronRight size={12} aria-hidden="true" />}
                      {open ? 'Hide' : 'Show'}
                      <span className="sr-only"> feature evidence for {row.label}</span>
                    </button>
                  </td>
                </tr>,
                open ? (
                  <tr key={`${row.key}-evidence`} className="border-t border-line/60">
                    <td colSpan={6} className="bg-raised/40 px-3 py-2">
                      <FeatureEvidence row={row} analysis={analysis} />
                    </td>
                  </tr>
                ) : null,
              ]
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function FeatureEvidence({ row, analysis }: { row: ParamRow; analysis: AnalysisResult }) {
  const entry =
    analysis.featureEvidence.find((candidate) =>
      candidate.param.toLowerCase().includes(row.key.toLowerCase().slice(0, 6)),
    ) ?? analysis.featureEvidence[0]

  if (!entry) {
    return <p className="text-[12px] text-muted">No recorded feature evidence for this parameter.</p>
  }

  return (
    <div>
      <p className="text-[11px] font-semibold uppercase tracking-wide text-muted">
        Top contributing features (importance weights)
      </p>
      <ul className="mt-1.5 space-y-1">
        {entry.features.map((feature) => (
          <li key={feature.name} className="flex items-center gap-2 text-[11px]">
            <span className="w-40 shrink-0 truncate text-muted" title={feature.name}>
              {feature.name}
            </span>
            <span className="h-2 flex-1 overflow-hidden rounded-full bg-raised">
              <span className="block h-full rounded-full bg-accent" style={{ width: `${Math.round(feature.weight * 100)}%` }} />
            </span>
            <span className="tnum w-10 text-right text-muted">{fmtPct(feature.weight, 0)}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
