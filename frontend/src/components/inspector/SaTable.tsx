import { TriangleAlert } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { fmtBytes, fmtInt } from '@/lib/format'
import type { SecurityAssociation } from '@/types/analysis'

/** Security association table (spec 10.2 item 5). */
export function SaTable({ sas }: { sas: SecurityAssociation[] }) {
  return (
    <Card data-testid="sa-table">
      <CardHeader title="Security associations" description={`${sas.length} active SA${sas.length === 1 ? '' : 's'}`} />
      <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Security associations table">
        <table className="w-full border-collapse text-xs">
          <caption className="sr-only">Security associations observed in the capture</caption>
          <thead>
            <tr className="bg-raised text-left text-muted">
              <th scope="col" className="px-3 py-2 font-medium">Kind</th>
              <th scope="col" className="px-3 py-2 font-medium">SPI out</th>
              <th scope="col" className="px-3 py-2 font-medium">SPI in</th>
              <th scope="col" className="px-3 py-2 font-medium">Mode</th>
              <th scope="col" className="px-3 py-2 font-medium">Encryption</th>
              <th scope="col" className="px-3 py-2 font-medium">Integrity</th>
              <th scope="col" className="px-3 py-2 font-medium">Packets</th>
              <th scope="col" className="px-3 py-2 font-medium">Bytes</th>
              <th scope="col" className="px-3 py-2 font-medium">First seen</th>
              <th scope="col" className="px-3 py-2 font-medium">Last seen</th>
              <th scope="col" className="px-3 py-2 font-medium">Seq range</th>
              <th scope="col" className="px-3 py-2 font-medium">Replay gaps</th>
            </tr>
          </thead>
          <tbody>
            {sas.map((sa) => (
              <tr key={sa.id} className="border-t border-line/60">
                <td className="px-3 py-2">
                  <Badge tone={sa.kind === 'IKE SA' ? 'info' : 'cyan'}>{sa.kind}</Badge>
                </td>
                <td className="px-3 py-2 font-mono text-muted">{sa.spiOut}</td>
                <td className="px-3 py-2 font-mono text-muted">{sa.spiIn}</td>
                <td className="px-3 py-2 text-muted">{sa.mode}</td>
                <td className="px-3 py-2 text-ink">{sa.encryption}</td>
                <td className="px-3 py-2 text-muted">{sa.integrity}</td>
                <td className="tnum px-3 py-2 text-ink">{fmtInt(sa.packets)}</td>
                <td className="tnum px-3 py-2 text-ink">{fmtBytes(sa.bytes)}</td>
                <td className="tnum px-3 py-2 text-muted">{sa.firstSeenSec.toFixed(3)} s</td>
                <td className="tnum px-3 py-2 text-muted">{sa.lastSeenSec.toFixed(3)} s</td>
                <td className="tnum px-3 py-2 text-muted">
                  {fmtInt(sa.seqMin)}–{fmtInt(sa.seqMax)}
                </td>
                <td className="px-3 py-2">
                  {sa.replayGaps > 0 ? (
                    <span className="inline-flex items-center gap-1 text-warn">
                      <TriangleAlert size={12} aria-hidden="true" />
                      <span className="tnum">{fmtInt(sa.replayGaps)}</span>
                    </span>
                  ) : (
                    <span className="tnum text-muted">0</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
