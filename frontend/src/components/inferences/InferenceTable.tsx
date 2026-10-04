import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { ConfidenceBar } from '@/components/ui/ConfidenceBar'
import { ProvenanceBadge } from '@/components/ui/ProvenanceBadge'
import { dhLabel } from '@/lib/dh'
import { setHighlightAndNavigate } from '@/lib/highlight'
import type { AnalysisResult, FieldStatus, Finding, Param } from '@/types/analysis'

/** Method text derives from the evidence source — never hard-coded per row. */
function methodFor(param: Param<unknown>, provided: boolean): string {
  if (!provided) return 'Not provided by the analysis API'
  if (param.source === 'parsed') return 'Direct parse'
  if (param.source === 'model') return 'Model classifier'
  if (param.source === 'measured') return 'Measured'
  return '—'
}

const UNOBSERVED: FieldStatus[] = ['UNKNOWN', 'NOT_OBSERVED', 'NOT_APPLICABLE']
const isUnobserved = (param: Param<unknown>): boolean =>
  (param.status !== undefined && UNOBSERVED.includes(param.status)) || param.value === 'unknown'

interface ParamRow {
  key: string
  label: string
  display: string
  param: Param<unknown>
  /** False when the analysis API never provides this row (ESN, PFS group). */
  provided: boolean
  rules: string[]
}

const PARAM_RULES: Record<string, string[]> = {
  dhGroup: ['R01', 'R11', 'weak-dh', 'weak-ike-dh'],
  ikeEncryption: ['R02', 'R08', 'weak-ike-cipher'],
  childEncryption: ['R02', 'R08', 'weak-cipher'],
  ikeIntegrity: ['R07', 'weak-ike-integ'],
  childIntegrity: ['R07', 'weak-integ', 'no-integ'],
  pfs: ['R04', 'no-pfs'],
  replay: ['R05', 'no-replay'],
  lifetime: ['R06', 'long-sa'],
  esn: ['R10'],
  traffic: ['R09'],
}

function natDisplay(p: AnalysisResult['protocol']): string {
  if (isUnobserved(p.natTraversal)) return 'not observed'
  return p.natTraversal.value ? 'Detected' : 'Not detected'
}

function boolDisplay(value: boolean, param: Param<unknown>): string {
  if (isUnobserved(param)) return 'not observed'
  return value ? 'Enabled' : 'Disabled'
}

function buildRows(analysis: AnalysisResult): ParamRow[] {
  const p = analysis.protocol
  const backend = analysis.posture !== undefined
  // Rows the analysis API never provides: in Live mode they read "not
  // provided", never invented values; fixtures keep their spec values.
  const pfsGroupDisplay = !backend && p.child.pfsGroup.value !== null ? dhLabel(p.child.pfsGroup.value) : 'not provided by the analysis API'
  const esnDisplay = !backend ? (p.child.esn.value ? 'Enabled' : 'Disabled') : 'not provided by the analysis API'
  const raw: ParamRow[] = [
    { key: 'ikeVersion', label: 'IKE version', display: isUnobserved(p.ikeVersion) ? 'not observed' : p.ikeVersion.value, param: p.ikeVersion, provided: true, rules: [] },
    { key: 'exchangeMode', label: 'Exchange mode', display: isUnobserved(p.exchangeMode) ? 'not observed' : p.exchangeMode.value, param: p.exchangeMode, provided: true, rules: [] },
    { key: 'mode', label: 'Tunnel / transport', display: isUnobserved(p.mode) ? 'not observed' : p.mode.value, param: p.mode, provided: true, rules: [] },
    { key: 'ipVersion', label: 'IP version', display: isUnobserved(p.ipVersion) ? 'not observed' : p.ipVersion.value, param: p.ipVersion, provided: true, rules: [] },
    { key: 'natTraversal', label: 'NAT traversal', display: natDisplay(p), param: p.natTraversal, provided: true, rules: [] },
    { key: 'ikeEncryption', label: 'IKE cipher', display: isUnobserved(p.ike.encryption) ? 'not observed' : p.ike.encryption.value, param: p.ike.encryption, provided: true, rules: PARAM_RULES.ikeEncryption ?? [] },
    { key: 'ikeIntegrity', label: 'IKE integrity', display: isUnobserved(p.ike.integrity) ? 'not observed' : p.ike.integrity.value, param: p.ike.integrity, provided: true, rules: PARAM_RULES.ikeIntegrity ?? [] },
    { key: 'prf', label: 'PRF', display: isUnobserved(p.ike.prf) ? 'not observed' : p.ike.prf.value, param: p.ike.prf, provided: true, rules: [] },
    { key: 'dhGroup', label: 'DH group', display: typeof p.ike.dhGroup.value === 'number' && !isUnobserved(p.ike.dhGroup) ? dhLabel(p.ike.dhGroup.value) : 'not observed', param: p.ike.dhGroup, provided: true, rules: PARAM_RULES.dhGroup ?? [] },
    { key: 'childEncryption', label: 'CHILD cipher', display: isUnobserved(p.child.encryption) ? 'not observed' : p.child.encryption.value, param: p.child.encryption, provided: true, rules: PARAM_RULES.childEncryption ?? [] },
    { key: 'childIntegrity', label: 'CHILD integrity', display: isUnobserved(p.child.integrity) ? 'not observed' : p.child.integrity.value, param: p.child.integrity, provided: true, rules: PARAM_RULES.childIntegrity ?? [] },
    { key: 'pfs', label: 'PFS', display: boolDisplay(p.child.pfs.value, p.child.pfs), param: p.child.pfs, provided: true, rules: PARAM_RULES.pfs ?? [] },
    { key: 'pfsGroup', label: 'PFS group', display: pfsGroupDisplay, param: { value: p.child.pfsGroup.value, provenance: p.child.pfs.provenance, confidence: p.child.pfs.confidence, status: p.child.pfs.status, source: p.child.pfs.source, note: 'The CHILD PFS group is never on the wire (rekeys are encrypted).' }, provided: !backend, rules: [] },
    { key: 'lifetime', label: 'CHILD lifetime', display: p.child.lifetimeSec.value === null || isUnobserved(p.child.lifetimeSec) ? 'not observed' : `${p.child.lifetimeSec.value} s`, param: p.child.lifetimeSec, provided: true, rules: PARAM_RULES.lifetime ?? [] },
    { key: 'replay', label: 'Replay protection', display: boolDisplay(p.child.replayProtection.value, p.child.replayProtection), param: p.child.replayProtection, provided: true, rules: PARAM_RULES.replay ?? [] },
    { key: 'esn', label: 'ESN', display: esnDisplay, param: { value: p.child.esn.value, provenance: p.child.esn.provenance, confidence: p.child.esn.confidence, status: p.child.esn.status, source: p.child.esn.source, note: 'ESN state is not reported by the analysis API.' }, provided: !backend, rules: PARAM_RULES.esn ?? [] },
  ]
  return raw
}

/** Inference table with per-parameter evidence expansion (spec 10.3 item 1). */
export function InferenceTable({ analysis }: { analysis: AnalysisResult }) {
  const backend = analysis.posture !== undefined
  const ruleVersion = analysis.posture?.ruleVersion ?? null
  const rows = useMemo(() => buildRows(analysis), [analysis])

  const relatedFindings = (row: ParamRow): Finding[] =>
    analysis.findings.filter((finding) => row.rules.includes(finding.ruleId))

  return (
    <Card data-testid="inference-table">
      <CardHeader
        title="Detected protocol parameters"
        description={
          backend
            ? `${rows.length} parameters · statuses from the backend analysis${ruleVersion ? ` (rule ${ruleVersion})` : ''}`
            : `${rows.length} parameters · simulated values`
        }
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
              const related = relatedFindings(row)
              const unobserved = !row.provided || isUnobserved(row.param)
              return <ParamTableRow key={row.key} row={row} related={related} unobserved={unobserved} />
            })}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

function ParamTableRow({ row, related, unobserved }: { row: ParamRow; related: Finding[]; unobserved: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <tr key={row.key} className="border-t border-line/60 align-top">
        <td className="px-3 py-2 text-ink">{row.label}</td>
        <td className="px-3 py-2 text-ink">
          <span className="break-all" title={row.param.note ?? undefined}>{row.display}</span>
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
          {unobserved ? (
            <Badge tone="neutral" title={row.param.note ?? 'Not observed in this capture.'}>Not observed</Badge>
          ) : (
            <ProvenanceBadge provenance={row.param.provenance} />
          )}
        </td>
        <td className="px-3 py-2">
          {unobserved ? (
            <span className="text-muted" title="No confidence: nothing was observed.">—</span>
          ) : (
            <ConfidenceBar value={row.param.confidence} ariaLabel={`${row.label} confidence`} />
          )}
        </td>
        <td className="px-3 py-2 text-muted">{methodFor(row.param, row.provided)}</td>
        <td className="px-3 py-2">
          <button
            type="button"
            aria-expanded={open}
            data-testid={`expand-${row.key}`}
            onClick={() => setOpen(!open)}
            className="inline-flex items-center gap-1 rounded-control px-1.5 py-1 text-[11px] text-accent hover:bg-raised"
          >
            {open ? <ChevronDown size={12} aria-hidden="true" /> : <ChevronRight size={12} aria-hidden="true" />}
            {open ? 'Hide' : 'Show'}
            <span className="sr-only"> feature evidence for {row.label}</span>
          </button>
        </td>
      </tr>
      {open ? (
        <tr key={`${row.key}-evidence`} className="border-t border-line/60">
          <td colSpan={6} className="bg-raised/40 px-3 py-2">
            <p className="text-[12px] text-muted">
              {row.param.note ?? 'No recorded feature evidence for this parameter.'}
            </p>
          </td>
        </tr>
      ) : null}
    </>
  )
}
