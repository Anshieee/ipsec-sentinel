import type { TrafficLabel } from '@/types/analysis'
import { FIXTURE_SEEDS } from '@/lib/prng'

export type FixtureId = 'A' | 'B' | 'C'

export interface FixtureParamSpec<T> {
  value: T
  /** Confidence of an inferred value; observed values are always 1. */
  confidence: number
}

export interface FixtureSpec {
  id: FixtureId
  label: string
  seed: number
  fileName: string
  /** Fixed timestamp keeps two builds of the same fixture deep-equal. */
  analyzedAt: string
  durationSec: number
  packets: number
  ikeHandshakes: number
  espStreams: number
  ahPackets: number
  ikeVersion: 'IKEv1' | 'IKEv2'
  exchangeMode: 'IKEv2 (IKE_SA_INIT + IKE_AUTH)' | 'Main Mode' | 'Aggressive Mode'
  mode: FixtureParamSpec<'tunnel' | 'transport'>
  ipVersion: 'IPv4' | 'IPv6'
  natTraversal: boolean
  ike: {
    encryption: string
    integrity: string
    prf: string
    dhGroup: number
    lifetimeSec: number | null
  }
  child: {
    encryption: FixtureParamSpec<string>
    integrity: FixtureParamSpec<string>
    pfs: FixtureParamSpec<boolean>
    pfsGroup: FixtureParamSpec<number | null>
    lifetimeSec: FixtureParamSpec<number | null>
    replayProtection: FixtureParamSpec<boolean>
    esn: FixtureParamSpec<boolean>
  }
  /** Simulated seconds at which a CREATE_CHILD_SA rekey occurs. */
  rekeyTimes: number[]
  trafficClasses: { label: TrafficLabel; probability: number }[]
  dominantClass: TrafficLabel
  overallConfidence: number
  ips: { src: string; dst: string }
  /** Total replay gaps reported across CHILD SAs. */
  replayGaps: number
  /** IKE UDP port: 500, or 4500 when NAT-T is present. */
  ikePort: number
  /** Handshake step timestamps in seconds (spec 8.7). */
  handshakeTimes: number[]
}

/** A: modern IKEv2 tunnel with AES-256-GCM. */
const SPEC_A: FixtureSpec = {
  id: 'A',
  label: 'Modern IKEv2 + AES-256-GCM',
  seed: FIXTURE_SEEDS.A,
  fileName: 'ipsec_ikev2_tunnel_aes256gcm.pcapng',
  analyzedAt: '2026-09-30T09:00:00.000Z',
  durationSec: 7320,
  packets: 48213,
  ikeHandshakes: 2,
  espStreams: 4,
  ahPackets: 0,
  ikeVersion: 'IKEv2',
  exchangeMode: 'IKEv2 (IKE_SA_INIT + IKE_AUTH)',
  mode: { value: 'tunnel', confidence: 0.98 },
  ipVersion: 'IPv4',
  natTraversal: false,
  ike: {
    encryption: 'AES-256-GCM-16',
    integrity: 'AEAD (implicit)',
    prf: 'PRF_HMAC_SHA2_384',
    dhGroup: 14,
    lifetimeSec: null,
  },
  child: {
    encryption: { value: 'AES-256-GCM-16', confidence: 0.97 },
    integrity: { value: 'AEAD (implicit)', confidence: 0.97 },
    pfs: { value: true, confidence: 0.92 },
    pfsGroup: { value: 14, confidence: 0.9 },
    lifetimeSec: { value: 3600, confidence: 0.94 },
    replayProtection: { value: true, confidence: 0.96 },
    esn: { value: false, confidence: 0.89 },
  },
  rekeyTimes: [3600],
  trafficClasses: [
    { label: 'Web Browsing', probability: 0.78 },
    { label: 'Video Streaming', probability: 0.08 },
    { label: 'VoIP', probability: 0.04 },
    { label: 'WhatsApp', probability: 0.03 },
    { label: 'E-mail', probability: 0.03 },
    { label: 'ICMP', probability: 0.02 },
    { label: 'Other', probability: 0.02 },
  ],
  dominantClass: 'Web Browsing',
  overallConfidence: 0.964,
  ips: { src: '10.10.0.2', dst: '203.0.113.10' },
  replayGaps: 0,
  ikePort: 500,
  handshakeTimes: [0.0, 0.012, 0.031, 0.058, 0.071],
}

/** B: legacy branch VPN with AES-CBC and HMAC-SHA1. */
const SPEC_B: FixtureSpec = {
  id: 'B',
  label: 'Legacy IKEv2 + AES-CBC + SHA-1',
  seed: FIXTURE_SEEDS.B,
  fileName: 'branch_vpn_aescbc_sha1.pcap',
  analyzedAt: '2026-09-30T09:05:00.000Z',
  durationSec: 68400,
  packets: 1204377,
  ikeHandshakes: 3,
  espStreams: 6,
  ahPackets: 0,
  ikeVersion: 'IKEv2',
  exchangeMode: 'IKEv2 (IKE_SA_INIT + IKE_AUTH)',
  mode: { value: 'tunnel', confidence: 0.95 },
  ipVersion: 'IPv4',
  natTraversal: true,
  ike: {
    encryption: 'AES-128-CBC',
    integrity: 'HMAC-SHA1-96',
    prf: 'PRF_HMAC_SHA1',
    dhGroup: 2,
    lifetimeSec: null,
  },
  child: {
    encryption: { value: 'AES-128-CBC', confidence: 0.93 },
    integrity: { value: 'HMAC-SHA1-96', confidence: 0.9 },
    pfs: { value: false, confidence: 0.88 },
    pfsGroup: { value: null, confidence: 0.88 },
    lifetimeSec: { value: 32400, confidence: 0.87 },
    replayProtection: { value: false, confidence: 0.81 },
    esn: { value: false, confidence: 0.85 },
  },
  rekeyTimes: [32400, 64800],
  trafficClasses: [
    { label: 'VoIP', probability: 0.71 },
    { label: 'WhatsApp', probability: 0.11 },
    { label: 'Video Streaming', probability: 0.07 },
    { label: 'Web Browsing', probability: 0.06 },
    { label: 'ICMP', probability: 0.02 },
    { label: 'E-mail', probability: 0.02 },
    { label: 'Other', probability: 0.01 },
  ],
  dominantClass: 'VoIP',
  overallConfidence: 0.918,
  ips: { src: '192.168.20.5', dst: '198.51.100.7' },
  replayGaps: 3,
  ikePort: 4500,
  handshakeTimes: [0.0, 0.012, 0.031, 0.058, 0.071],
}

/** C: obsolete IKEv1 Aggressive Mode with 3DES over IPv6. */
const SPEC_C: FixtureSpec = {
  id: 'C',
  label: 'Obsolete IKEv1 Aggressive + 3DES',
  seed: FIXTURE_SEEDS.C,
  fileName: 'legacy_ikev1_transport_3des_v6.pcap',
  analyzedAt: '2026-09-30T09:10:00.000Z',
  durationSec: 4120,
  packets: 9377,
  ikeHandshakes: 2,
  espStreams: 2,
  ahPackets: 0,
  ikeVersion: 'IKEv1',
  exchangeMode: 'Aggressive Mode',
  mode: { value: 'transport', confidence: 0.82 },
  ipVersion: 'IPv6',
  natTraversal: false,
  ike: {
    encryption: '3DES-CBC',
    integrity: 'HMAC-SHA1-96',
    prf: 'PRF_HMAC_SHA1',
    dhGroup: 1,
    lifetimeSec: 28800,
  },
  child: {
    encryption: { value: '3DES-CBC', confidence: 0.78 },
    integrity: { value: 'HMAC-SHA1-96', confidence: 0.74 },
    pfs: { value: false, confidence: 0.7 },
    pfsGroup: { value: null, confidence: 0.7 },
    lifetimeSec: { value: 3600, confidence: 0.66 },
    replayProtection: { value: true, confidence: 0.72 },
    esn: { value: false, confidence: 0.69 },
  },
  rekeyTimes: [],
  trafficClasses: [
    { label: 'ICMP', probability: 0.44 },
    { label: 'Web Browsing', probability: 0.22 },
    { label: 'E-mail', probability: 0.14 },
    { label: 'VoIP', probability: 0.08 },
    { label: 'Video Streaming', probability: 0.05 },
    { label: 'WhatsApp', probability: 0.04 },
    { label: 'Other', probability: 0.03 },
  ],
  dominantClass: 'ICMP',
  overallConfidence: 0.731,
  ips: { src: '2001:db8::2', dst: '2001:db8:ffff::1' },
  replayGaps: 0,
  ikePort: 500,
  handshakeTimes: [0.0, 0.041, 0.083, 0.12, 0.16, 0.201, 0.24],
}

export const FIXTURE_SPECS: Record<FixtureId, FixtureSpec> = { A: SPEC_A, B: SPEC_B, C: SPEC_C }

export const FIXTURE_IDS: FixtureId[] = ['A', 'B', 'C']

export function fixtureSpec(id: FixtureId): FixtureSpec {
  return FIXTURE_SPECS[id]
}

/**
 * Fixture selection from a file name (spec 8.3): `gcm` -> A, `cbc` -> B,
 * `ikev1`/`legacy` -> C, otherwise `hashString(name) % 3`.
 */
export function fixtureIdForFileName(fileName: string, hash: (s: string) => number): FixtureId {
  const lower = fileName.toLowerCase()
  if (lower.includes('gcm')) return 'A'
  if (lower.includes('cbc')) return 'B'
  if (lower.includes('ikev1') || lower.includes('legacy')) return 'C'
  const bucket = hash(fileName) % 3
  return bucket === 0 ? 'A' : bucket === 1 ? 'B' : 'C'
}
