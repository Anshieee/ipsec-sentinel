import { useRef, useState, type DragEvent } from 'react'
import { CheckCircle2, Upload, X } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card } from '@/components/ui/Card'
import { cn } from '@/components/ui/cn'
import { useSentinel } from '@/store/useSentinel'
import { fmtBytes, fmtInt } from '@/lib/format'
import type { UploadStatus } from '@/store/slices/uploadSlice'

const STAGE_LABEL: Record<UploadStatus, string> = {
  idle: '',
  uploading: 'Uploading',
  parsing: 'Parsing packets',
  inferring: 'Running AI inference',
  complete: 'Analysis complete',
  error: '',
}

interface StreamSummary {
  packets: number
  ike: number
  esp: number
  ah: number
  other?: number
}

/** Upload and capture drop zone (spec 10.1 B.1). */
export function UploadZone() {
  const upload = useSentinel((s) => s.upload)
  const startUpload = useSentinel((s) => s.startUpload)
  const cancelUpload = useSentinel((s) => s.cancelUpload)
  const inputRef = useRef<HTMLInputElement | null>(null)
  const [dragOver, setDragOver] = useState(false)

  const processing =
    upload.status === 'uploading' || upload.status === 'parsing' || upload.status === 'inferring'
  const summary: StreamSummary | null =
    upload.status === 'complete' && upload.summary
      ? {
          packets: upload.summary.packets,
          ike: upload.summary.ikeHandshakes,
          esp: upload.summary.espStreams,
          ah: upload.summary.ahPackets,
        }
      : null

  const onDrop = (event: DragEvent<HTMLDivElement>): void => {
    event.preventDefault()
    setDragOver(false)
    const file = event.dataTransfer.files?.[0]
    if (file) void startUpload(file)
  }

  return (
    <Card data-testid="upload-zone">
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="sr-only"
        aria-label="Upload a .pcap or .pcapng trace"
        data-testid="upload-zone-input"
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) void startUpload(file)
          event.target.value = ''
        }}
      />

      <div
        role="button"
        tabIndex={0}
        aria-describedby="upload-zone-constraints"
        data-testid="upload-zone-drop"
        onClick={() => inputRef.current?.click()}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault()
            inputRef.current?.click()
          }
        }}
        onDragOver={(event) => {
          event.preventDefault()
          setDragOver(true)
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={onDrop}
        className={cn(
          'flex cursor-pointer flex-col items-center justify-center rounded-card border-2 border-dashed px-4 py-6 text-center transition-colors',
          dragOver ? 'border-accent bg-accent/10' : 'border-line hover:border-accent/60',
        )}
      >
        <Upload size={20} className="text-muted" aria-hidden="true" />
        <p className="mt-2 text-[13px] text-ink">
          Drag and drop a .pcap or .pcapng trace, or click to browse
        </p>
        <p id="upload-zone-constraints" className="mt-1 text-[11px] text-muted">
          Maximum 200 MB. Processed locally in demo mode.
        </p>
      </div>

      {upload.status === 'error' && upload.error ? (
        <div
          role="alert"
          data-testid="upload-error"
          className="mt-3 rounded-control border border-danger/40 bg-danger/10 px-3 py-2 text-xs text-danger"
        >
          <p className="font-medium">Upload failed</p>
          <p className="mt-0.5 text-[12px]">{upload.error}</p>
        </div>
      ) : null}

      {processing ? (
        <div className="mt-3 space-y-2" data-testid="upload-progress">
          <div className="flex items-center justify-between gap-2 text-xs">
            <span className="text-ink">{STAGE_LABEL[upload.status]}</span>
            <span className="tnum text-muted">{Math.round(upload.progress)}%</span>
          </div>
          <div
            role="progressbar"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={Math.round(upload.progress)}
            aria-label="Upload progress"
            className="h-2 overflow-hidden rounded-full bg-raised"
          >
            <div
              className="h-full rounded-full bg-accent-solid transition-[width]"
              style={{ width: `${upload.progress}%` }}
            />
          </div>
          <div className="flex items-center justify-between gap-2 text-[11px] text-muted">
            <span className="truncate">
              {upload.fileName} {upload.fileSize ? `· ${fmtBytes(upload.fileSize)}` : ''}
            </span>
            <Button variant="ghost" size="sm" onClick={cancelUpload}>
              <X size={12} aria-hidden="true" />
              Cancel
            </Button>
          </div>
        </div>
      ) : null}

      {summary ? (
        <div className="mt-3 rounded-control border border-safe/40 bg-safe/10 p-3" data-testid="upload-complete">
          <p className="flex items-center gap-1.5 text-xs font-medium text-safe">
            <CheckCircle2 size={14} aria-hidden="true" />
            Analysis complete
          </p>
          <table className="mt-2 w-full text-xs">
            <caption className="sr-only">Instant stream summary</caption>
            <thead>
              <tr className="text-left text-muted">
                <th className="py-1 font-medium">Packets</th>
                <th className="py-1 font-medium">IKE</th>
                <th className="py-1 font-medium">ESP</th>
                <th className="py-1 font-medium">AH</th>
                <th className="py-1 font-medium">Other</th>
              </tr>
            </thead>
            <tbody>
              <tr className="tnum text-ink">
                <td className="py-1">{fmtInt(summary.packets)}</td>
                <td className="py-1">{fmtInt(summary.ike)}</td>
                <td className="py-1">{fmtInt(summary.esp)}</td>
                <td className="py-1">{fmtInt(summary.ah)}</td>
                <td className="py-1">{fmtInt(summary.other ?? 0)}</td>
              </tr>
            </tbody>
          </table>
        </div>
      ) : null}
    </Card>
  )
}
