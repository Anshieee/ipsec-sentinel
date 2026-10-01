import { Link } from 'react-router-dom'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { ProvenanceBadge } from '@/components/ui/ProvenanceBadge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { useSentinel, useDerived } from '@/store/useSentinel'
import { dhLabel } from '@/lib/dh'
import { fmtPct } from '@/lib/format'
import { setHighlightAndNavigate } from '@/lib/highlight'
import type { AnalysisResult, Finding, Param } from '@/types/analysis'

/** Rules that attach a severity badge to a given crypto row. */
const ROW_RULES: Record<string, string[]> = {
  ikeEncryption: ['R02', 'R08'],
  childEncryption: ['R02', 'R08'],
  ikeIntegrity: ['R07'],
  childIntegrity: ['R07'],
  dhGroup: ['R01', 'R11'],
  pfs: ['R04'],
}

interface RowProps {
  label: string
  value: string
  param: Param<unknown>
  rules: Finding[]
}

function CryptoRow({ label, value, param, rules }: RowProps) {
  return (
    <div className="flex items-start justify-between gap-3 py-2">
      <div className="min-w-0">
        <p className="text-[12px] text-muted">{label}</p>
        <p className="break-words text-[13px] text-ink">{value}</p>
      </div>
      <div className="flex shrink-0 flex-wrap items-center justify-end gap-1.5">
        {rules.map((finding) => (
          <Link
            key={finding.id}
            to="/audit"
            onClick={() => setHighlightAndNavigate(finding.id)}
            title={finding.title}
            className="inline-flex"
          >
            <SeverityBadge severity={finding.severity} compact />
            <span className="sr-only">Finding {finding.ruleId}: {finding.title}</span>
          </Link>
        ))}
        <ProvenanceBadge provenance={param.provenance} iconOnly />
        {param.provenance === 'inferred' ? (
          <span className="tnum text-2xs text-muted">{fmtPct(param.confidence)}</span>
        ) : null}
      </div>
    </div>
  )
}

function findRules(findings: Finding[], keys: string[]): Finding[] {
  return findings.filter((finding) => keys.includes(finding.ruleId))
}

/** Protocol and cryptographic suite card (spec 10.1 B.2). */
export function CryptoCard({ analysis }: { analysis: AnalysisResult }) {
  const derived = useDerived()
  const minRuleConfidence = useSentinel((s) => s.settings.minRuleConfidence)
  const p = analysis.protocol
  const ikev2 = p.ikeVersion.value === 'IKEv2'
  const findings = derived.findings

  const pfsLabel = p.child.pfs.value
    ? `Enabled${p.child.pfsGroup.value !== null ? ` · ${dhLabel(p.child.pfsGroup.value)}` : ''}`
    : 'Disabled'

  return (
    <Card data-testid="crypto-card">
      <CardHeader
        title={ikev2 ? 'Protocol & cryptographic suite' : 'Protocol & cryptographic suite (IKEv1)'}
        description={analysis.protocol.exchangeMode.value}
      />

      <section aria-label={ikev2 ? 'IKE SA' : 'Phase 1 (ISAKMP SA)'}>
        <h3 className="border-b border-line pb-1 text-xs font-semibold uppercase tracking-wide text-muted">
          {ikev2 ? 'IKE SA' : 'Phase 1 (ISAKMP SA)'}
        </h3>
        <div className="divide-y divide-line/60">
          <CryptoRow
            label="Encryption"
            value={p.ike.encryption.value}
            param={p.ike.encryption}
            rules={findRules(findings, ROW_RULES.ikeEncryption ?? [])}
          />
          <CryptoRow
            label="Integrity / Authentication"
            value={p.ike.integrity.value}
            param={p.ike.integrity}
            rules={findRules(findings, ROW_RULES.ikeIntegrity ?? [])}
          />
          <CryptoRow label="PRF" value={p.ike.prf.value} param={p.ike.prf} rules={[]} />
          <CryptoRow
            label="DH group"
            value={dhLabel(p.ike.dhGroup.value)}
            param={p.ike.dhGroup}
            rules={findRules(findings, ROW_RULES.dhGroup ?? [])}
          />
          <CryptoRow label="IP version" value={p.ipVersion.value} param={p.ipVersion} rules={[]} />
          <CryptoRow
            label="NAT-T"
            value={p.natTraversal.value ? 'Detected' : 'Not detected'}
            param={p.natTraversal}
            rules={[]}
          />
          <CryptoRow
            label="Mode"
            value={p.mode.value === 'tunnel' ? 'Tunnel mode' : 'Transport mode'}
            param={p.mode}
            rules={[]}
          />
        </div>
      </section>

      <section aria-label={ikev2 ? 'CHILD SA' : 'Phase 2 (Quick Mode SA)'} className="mt-4">
        <h3 className="border-b border-line pb-1 text-xs font-semibold uppercase tracking-wide text-muted">
          {ikev2 ? 'CHILD SA' : 'Phase 2 (Quick Mode SA)'}
        </h3>
        <div className="divide-y divide-line/60">
          <CryptoRow
            label="Encryption"
            value={p.child.encryption.value}
            param={p.child.encryption}
            rules={findRules(findings, ROW_RULES.childEncryption ?? [])}
          />
          <CryptoRow
            label="Integrity / Authentication"
            value={p.child.integrity.value}
            param={p.child.integrity}
            rules={findRules(findings, ROW_RULES.childIntegrity ?? [])}
          />
          <div className="flex items-center justify-between gap-3 py-2">
            <div>
              <p className="text-[12px] text-muted">PFS</p>
              <p className="text-[13px] text-ink">{pfsLabel}</p>
            </div>
            <div className="flex items-center gap-1.5">
              {findRules(findings, ROW_RULES.pfs ?? []).map((finding) => (
                <Link key={finding.id} to="/audit" onClick={() => setHighlightAndNavigate(finding.id)} className="inline-flex">
                  <SeverityBadge severity={finding.severity} compact />
                  <span className="sr-only">Finding {finding.ruleId}</span>
                </Link>
              ))}
              <Badge tone={p.child.pfs.value ? 'safe' : 'danger'}>
                {p.child.pfs.value ? 'Enabled' : 'Disabled'}
              </Badge>
            </div>
          </div>
          <div className="py-2 text-[12px] text-muted">
            Rows below the rule confidence threshold of {fmtPct(minRuleConfidence)} are marked unknown by the rule
            engine.
          </div>
        </div>
      </section>
    </Card>
  )
}
