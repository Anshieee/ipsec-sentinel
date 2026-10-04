import { Drawer } from '@/components/ui/Drawer'
import { Kbd } from '@/components/ui/Kbd'
import { useSentinel } from '@/store/useSentinel'

interface ShortcutRow {
  keys: string[]
  description: string
}

const SHORTCUTS: ShortcutRow[] = [
  { keys: ['/'], description: 'Focus global search' },
  { keys: ['u'], description: 'Open the file picker for a .pcap / .pcapng trace' },
  { keys: ['l'], description: 'Toggle the simulated live capture' },
  { keys: ['r'], description: 'Open or close the report drawer' },
  { keys: ['?'], description: 'Open this shortcut list' },
  { keys: ['Esc'], description: 'Close the topmost overlay' },
  { keys: ['←', '→'], description: 'Move between tabs, menu options and search results' },
  { keys: ['↑', '↓'], description: 'Move through search results' },
  { keys: ['Enter'], description: 'Activate the focused result or control' },
]

/** Keyboard shortcut reference, opened by `?` or the analyst menu. */
export function HelpDialog() {
  const helpOpen = useSentinel((s) => s.helpOpen)
  const setHelpOpen = useSentinel((s) => s.setHelpOpen)

  return (
    <Drawer
      open={helpOpen}
      onClose={() => setHelpOpen(false)}
      title="Keyboard shortcuts"
      description="Shortcuts are ignored while focus is inside a text field."
      testId="help-dialog"
    >
      <ul className="divide-y divide-border">
        {SHORTCUTS.map((row) => (
          <li key={row.description} className="flex items-center justify-between gap-3 py-2.5">
            <span className="text-[13px] text-text-primary">{row.description}</span>
            <span className="flex shrink-0 items-center gap-1">
              {row.keys.map((key) => (
                <Kbd key={key}>{key}</Kbd>
              ))}
            </span>
          </li>
        ))}
      </ul>
      <p className="mt-4 text-xs leading-5 text-text-secondary">
        Every shortcut has an equivalent pointer control in the header, sidebar and page toolbars.
      </p>
    </Drawer>
  )
}
