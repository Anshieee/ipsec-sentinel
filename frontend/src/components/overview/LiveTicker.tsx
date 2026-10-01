import { useMemo } from 'react'
import { LineChart, Line, ResponsiveContainer, YAxis } from 'recharts'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { useSentinel } from '@/store/useSentinel'
import { fmtInt } from '@/lib/format'
import { TONE_HEX } from '@/lib/severity'
import type { PacketRow } from '@/types/analysis'

const PROTO_TONE: Record<PacketRow['proto'], 'info' | 'cyan' | 'warn' | 'neutral' | 'danger'> = {
  IKE: 'info',
  ESP: 'cyan',
  AH: 'warn',
  UDP: 'neutral',
  OTHER: 'danger',
}

/** Live ticker: last 8 packets plus a packets-per-tick sparkline (spec 10.1 C.3). */
export function LiveTicker() {
  const live = useSentinel((s) => s.live)
  const liveMode = useSentinel((s) => s.settings.dataSource) === 'live'
  const recent = live.recent

  const sparkline = useMemo(() => {
    const buckets = new Map<number, number>()
    for (const packet of recent) {
      const bucket = Math.floor(packet.timeSec)
      buckets.set(bucket, (buckets.get(bucket) ?? 0) + 1)
    }
    return Array.from(buckets.entries())
      .sort((a, b) => a[0] - b[0])
      .map(([second, count]) => ({ second, count }))
  }, [recent])

  if (live.status !== 'capturing') return null

  const last8 = recent.slice(-8).reverse()

  return (
    <Card data-testid="live-ticker">
      <CardHeader
        title="Live ticker"
        description={`${fmtInt(live.counters.packets)} packets · ${fmtInt(live.elapsedSec)} s elapsed`}
        actions={<Badge tone="cyan">Capturing</Badge>}
      />
      {liveMode ? (
        <p className="px-4 pt-1 text-[11px] text-muted" title="The live capture stream is simulated; upload a pcap for real analysis.">
          SIMULATED stream — upload a trace for real analysis.
        </p>
      ) : null}

      <figure className="m-0">
        <div className="h-16 w-full" aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={sparkline}>
              <YAxis hide domain={[0, 'auto']} />
              <Line type="monotone" dataKey="count" stroke={TONE_HEX.cyan} strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
        <figcaption className="sr-only">Packets per second observed during the live capture.</figcaption>
        <table className="sr-only">
          <caption>Packets per second</caption>
          <thead>
            <tr>
              <th scope="col">Second</th>
              <th scope="col">Packets</th>
            </tr>
          </thead>
          <tbody>
            {sparkline.map((point) => (
              <tr key={point.second}>
                <td>{point.second}</td>
                <td>{point.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </figure>

      <ul className="mt-2 space-y-1" aria-live="off">
        {last8.map((packet) => (
          <li key={`${packet.no}-${packet.timeSec}`} className="flex items-center gap-2 text-[11px]">
            <span className="tnum w-12 text-muted">{packet.timeSec.toFixed(3)}</span>
            <Badge tone={PROTO_TONE[packet.proto]}>{packet.proto}</Badge>
            <span className="tnum text-muted">{fmtInt(packet.length)} B</span>
            <span className="truncate text-ink">{packet.info}</span>
          </li>
        ))}
      </ul>
    </Card>
  )
}
