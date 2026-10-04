import { useMemo, useState } from 'react'
import { PageScaffold } from './PageScaffold'
import { StatsStrip } from '@/components/inspector/StatsStrip'
import { FilterBar, EMPTY_FILTERS, type PacketFilters } from '@/components/inspector/FilterBar'
import { PacketTable } from '@/components/inspector/PacketTable'
import { PacketDetail } from '@/components/inspector/PacketDetail'
import { SaTable } from '@/components/inspector/SaTable'
import { InspectorCharts } from '@/components/inspector/InspectorCharts'
import { NoIpsecBanner, isNoIpsec } from '@/components/ui/NoIpsecBanner'
import { useAnalysis, useSentinel } from '@/store/useSentinel'
import type { PacketRow } from '@/types/analysis'

function matches(packet: PacketRow, filters: PacketFilters, initiatorIp: string): boolean {
  if (filters.protocols.length > 0 && !filters.protocols.includes(packet.proto)) return false
  if (filters.direction === 'Outbound' && packet.src !== initiatorIp) return false
  if (filters.direction === 'Inbound' && packet.src === initiatorIp) return false
  const needle = filters.query.trim().toLowerCase()
  if (needle.length > 0) {
    const haystack = `${packet.src} ${packet.dst} ${packet.spi ?? ''} ${packet.info}`.toLowerCase()
    if (!haystack.includes(needle)) return false
  }
  return true
}

/** Traffic Inspector & PCAP Parser (`/inspector`), spec 10.2. */
export function InspectorPage() {
  const analysis = useAnalysis()
  const live = useSentinel((s) => s.live)
  const density = useSentinel((s) => s.settings.density)
  const [filters, setFilters] = useState<PacketFilters>(EMPTY_FILTERS)
  const [selected, setSelected] = useState<PacketRow | null>(null)

  const initiatorIp = useMemo(() => analysis?.packets[0]?.src ?? '', [analysis])

  // Backend-mapped results carry no packet rows: one clear notice
  // instead of empty tables/boxes (never invented rows).
  const noPacketDetail = analysis?.posture !== undefined && analysis.packets.length === 0 && analysis.sas.length === 0

  const rows = useMemo(
    () => (analysis ? analysis.packets.filter((packet) => matches(packet, filters, initiatorIp)) : []),
    [analysis, filters, initiatorIp],
  )

  return (
    <PageScaffold
      title="Traffic Inspector"
      description="Packet table, decoded headers, security associations and traffic charts parsed from the capture."
      testId="page-inspector"
    >
      {analysis ? (
        <div className="space-y-4">
          {isNoIpsec(analysis) ? <NoIpsecBanner /> : null}
          <StatsStrip
            analysis={analysis}
            counters={live.counters}
            elapsedSec={live.elapsedSec}
          />
          {noPacketDetail ? (
            <p className="rounded-control border border-border bg-bg-card/50 p-4 text-[13px] text-text-secondary" data-testid="no-packet-detail">
              Packet-level detail is not returned by the analysis API; use{' '}
              <code className="font-mono text-text-primary">ipsec-analyze analyze --json</code> for evidence.
            </p>
          ) : (
            <>
              <FilterBar filters={filters} onChange={setFilters} />
              <div className="grid grid-cols-12 gap-4">
                <div className="col-span-12 xl:col-span-8">
                  <PacketTable
                    rows={rows}
                    sampledTotal={analysis.packets.length}
                    captureTotal={analysis.summary.packets}
                    selectedNo={selected?.no ?? null}
                    onSelect={setSelected}
                    density={density}
                  />
                </div>
                <div className="col-span-12 xl:col-span-4">
                  <PacketDetail packet={selected} />
                </div>
              </div>
              <SaTable sas={analysis.sas} />
              <InspectorCharts analysis={analysis} />
            </>
          )}
        </div>
      ) : null}
    </PageScaffold>
  )
}
