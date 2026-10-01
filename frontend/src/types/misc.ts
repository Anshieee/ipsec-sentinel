import type { PolicyId, Provenance, Severity, TrafficLabel } from './analysis'

export type ModelType = 'Rule-based' | 'GBM' | 'CNN' | 'Transformer'

export interface ModelEntry {
  id: string
  name: string
  task: string
  version: string
  type: ModelType
  macroF1: number
  lastTrained: string
  latencyMs: number
  params: string
}

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'

export interface LogLine {
  id: string
  ts: string
  level: LogLevel
  source: string
  message: string
}

export interface PolicyOverrides {
  /** Maximum accepted CHILD SA lifetime in seconds for rule R06. */
  childLifetimeMaxSec?: number
  /** Rule id -> replacement severity. */
  severity?: Partial<Record<string, Severity>>
  /** Rule ids that are not evaluated under this policy. */
  disabled?: string[]
}

export interface Policy {
  id: PolicyId
  name: string
  summary: string
  overrides: PolicyOverrides
}

export type DhStatus = 'Broken' | 'Deprecated' | 'Acceptable' | 'Recommended'

export interface DhGroup {
  group: number
  name: string
  kind: 'MODP' | 'ECP'
  bits: number
  /** Numeric security level; the literal `'below 64'` is treated as 64 for sorting and charting. */
  securityBits: number | 'below 64'
  keBytes: number
  status: DhStatus
}

export type TrafficExposure = 'Inferable' | 'Uninferable'

export interface WhatIfConfig {
  ikeVersion: 'IKEv1' | 'IKEv2'
  exchangeMode: 'IKEv2 (IKE_SA_INIT + IKE_AUTH)' | 'Main Mode' | 'Aggressive Mode'
  ikeEncryption: string
  ikeIntegrity: string
  dhGroup: number
  pfs: boolean
  pfsGroup: number | null
  childEncryption: string
  childIntegrity: string
  lifetimeSec: number
  replayProtection: boolean
  esn: boolean
  mode: 'tunnel' | 'transport'
  trafficExposure: TrafficExposure
}

export interface Notification {
  id: string
  severity: 'info' | 'warn' | 'critical' | 'success'
  message: string
  at: string
  read: boolean
}

/** A single parameter row as rendered on the inferences page. */
export interface InferenceRow {
  key: string
  label: string
  display: string
  provenance: Provenance
  confidence: number
  method: 'Direct parse' | 'Rule-based heuristic' | 'GBM classifier' | 'Sequence model'
  findingRuleId?: string
}

export interface ConfusionMatrix {
  labels: TrafficLabel[]
  /** rows = actual, columns = predicted; each row sums to 1. */
  rows: number[][]
}
