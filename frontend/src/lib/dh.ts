import type { DhGroup, DhStatus } from '@/types/misc'

/** Diffie-Hellman groups used across the app, fixtures and reports (spec 10.3). */
export const DH_GROUPS: DhGroup[] = [
  { group: 1, name: 'MODP-768', kind: 'MODP', bits: 768, securityBits: 'below 64', keBytes: 96, status: 'Broken' },
  { group: 2, name: 'MODP-1024', kind: 'MODP', bits: 1024, securityBits: 80, keBytes: 128, status: 'Deprecated' },
  { group: 5, name: 'MODP-1536', kind: 'MODP', bits: 1536, securityBits: 90, keBytes: 192, status: 'Deprecated' },
  { group: 14, name: 'MODP-2048', kind: 'MODP', bits: 2048, securityBits: 112, keBytes: 256, status: 'Acceptable' },
  { group: 15, name: 'MODP-3072', kind: 'MODP', bits: 3072, securityBits: 128, keBytes: 384, status: 'Acceptable' },
  { group: 16, name: 'MODP-4096', kind: 'MODP', bits: 4096, securityBits: 152, keBytes: 512, status: 'Acceptable' },
  { group: 19, name: 'ECP-256', kind: 'ECP', bits: 256, securityBits: 128, keBytes: 64, status: 'Recommended' },
  { group: 20, name: 'ECP-384', kind: 'ECP', bits: 384, securityBits: 192, keBytes: 96, status: 'Recommended' },
  { group: 21, name: 'ECP-521', kind: 'ECP', bits: 521, securityBits: 256, keBytes: 132, status: 'Recommended' },
]

export const DH_STATUS_TONE: Record<DhStatus, 'danger' | 'orange' | 'info' | 'safe'> = {
  Broken: 'danger',
  Deprecated: 'orange',
  Acceptable: 'info',
  Recommended: 'safe',
}

export function dhGroup(group: number): DhGroup | undefined {
  return DH_GROUPS.find((g) => g.group === group)
}

/** Numeric security level; "below 64" is treated as 64 for sorting and charting. */
export function securityBits(group: number): number {
  const entry = dhGroup(group)
  if (!entry) return 0
  return entry.securityBits === 'below 64' ? 64 : entry.securityBits
}

/** True when the value is listed as "below 64" in the table. */
export function isSecurityBitsFootnoted(group: number): boolean {
  return dhGroup(group)?.securityBits === 'below 64'
}

/** Human label, for example `Group 14 (MODP-2048)`. */
export function dhLabel(group: number): string {
  const entry = dhGroup(group)
  if (!entry) return `Group ${group} (unknown)`
  return `Group ${group} (${entry.name})`
}

export function dhStatus(group: number): DhStatus | undefined {
  return dhGroup(group)?.status
}

/** Key-exchange payload size in bytes for the group, 0 when unknown. */
export function dhKeBytes(group: number): number {
  return dhGroup(group)?.keBytes ?? 0
}
