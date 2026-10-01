import { useMemo, useState } from 'react'
import { Check, Copy, Lock } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { useSentinel } from '@/store/useSentinel'
import { hexDumpText, hexRows, packetBytes } from '@/lib/hexdump'
import { fmtInt } from '@/lib/format'
import type { PacketRow } from '@/types/analysis'

interface Field {
  label: string
  value: string
}

function ikeFields(packet: PacketRow): Field[] {
  return [
    { label: 'Initiator SPI', value: packet.spi ?? '—' },
    { label: 'Responder SPI', value: '0x4b2f9a1c7d3e5f60' },
    { label: 'Next Payload', value: 'Security Association (33)' },
    { label: 'Version', value: '2.0' },
    { label: 'Exchange Type', value: 'IKE_SA_INIT (34)' },
    { label: 'Flags', value: 'Initiator, Version' },
    { label: 'Message ID', value: '0x00000000' },
    { label: 'Length', value: `${fmtInt(packet.length)} bytes` },
  ]
}

function espFields(packet: PacketRow): Field[] {
  return [
    { label: 'SPI', value: packet.spi ?? '—' },
    { label: 'Sequence Number', value: String(packet.seq ?? '—') },
    { label: 'Payload length', value: `${fmtInt(Math.max(0, packet.length - 30))} bytes` },
    { label: 'Estimated padding', value: `${packet.length % 16} bytes` },
    { label: 'Estimated IV/ICV', value: '16 / 16 bytes (AES-GCM)' },
  ]
}

/** Selected packet detail: decoded header table plus deterministic hex dump. */
export function PacketDetail({ packet }: { packet: PacketRow | null }) {
  const [copied, setCopied] = useState(false)
  const bytes = useMemo(() => (packet ? packetBytes(packet) : null), [packet])
  const rows = useMemo(() => (bytes ? hexRows(bytes) : []), [bytes])

  if (!packet || !bytes) {
    return (
      <Card data-testid="packet-detail">
        <CardHeader title="Packet detail" description="Select a row to decode the header." />
        <p className="text-[13px] text-muted">No packet selected.</p>
      </Card>
    )
  }

  const fields = packet.proto === 'IKE' ? ikeFields(packet) : espFields(packet)
  const encrypted = packet.proto === 'ESP' || packet.proto === 'AH'

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(hexDumpText(bytes))
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      useSentinel.getState().notify({ severity: 'warn', message: 'Clipboard unavailable in this browser.' })
    }
  }

  return (
    <Card data-testid="packet-detail">
      <CardHeader
        title={`Packet #${fmtInt(packet.no)}`}
        description={`${packet.src} → ${packet.dst} · ${packet.proto} · ${fmtInt(packet.length)} B`}
        actions={
          <Button variant="secondary" size="sm" onClick={() => void copy()}>
            {copied ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
            {copied ? 'Copied' : 'Copy hex'}
          </Button>
        }
      />

      {encrypted ? (
        <p className="mb-2 rounded-control border border-line bg-raised px-2.5 py-1.5 text-[12px] text-muted">
          Payload is encrypted. Only the header is observable.
        </p>
      ) : null}

      <dl className="grid grid-cols-[minmax(0,auto)_1fr] gap-x-3 gap-y-1 text-xs">
        {fields.map((field) => (
          <div key={field.label} className="contents">
            <dt className="text-muted">{field.label}</dt>
            <dd className="break-all font-mono text-ink">{field.value}</dd>
          </div>
        ))}
        <div className="contents">
          <dt className="text-muted">Protocol</dt>
          <dd>
            <Badge tone="cyan">{packet.proto}</Badge>
          </dd>
        </div>
      </dl>

      <div className="mt-3">
        <p className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">
          <Lock size={11} aria-hidden="true" />
          Hex dump (first 64 bytes)
        </p>
        <div className="overflow-x-auto rounded-control border border-line bg-raised/60 p-2">
          <table className="w-full font-mono text-[11px]">
            <caption className="sr-only">Hex dump of packet {packet.no}</caption>
            <thead className="sr-only">
              <tr>
                <th scope="col">Offset</th>
                <th scope="col">Hex</th>
                <th scope="col">ASCII</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.offset}>
                  <td className="pr-3 text-muted">{row.offset}</td>
                  <td className="pr-3 whitespace-pre text-ink">{row.hex}</td>
                  <td className="text-highlight">{row.ascii}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Card>
  )
}
