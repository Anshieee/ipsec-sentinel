import type { PolicyId } from '@/types/analysis'
import { configureMock } from '@/api/mock'
import { defaultDataSource, type DataSource } from '@/api/client'
import type { SliceCreator } from '../types'

export type Density = 'comfortable' | 'compact'

export interface Settings {
  density: Density
  uncertainThreshold: number
  minRuleConfidence: number
  defaultPolicyId: PolicyId
  defaultSource: 'A' | 'B' | 'C'
  simulateErrors: boolean
  /** Runtime backend selector (Mock = fixtures, Live = real API). */
  dataSource: DataSource
}

export const DEFAULT_SETTINGS: Settings = {
  density: 'comfortable',
  uncertainThreshold: 0.6,
  minRuleConfidence: 0.6,
  defaultPolicyId: 'nist-baseline',
  defaultSource: 'A',
  simulateErrors: false,
  dataSource: defaultDataSource(),
}

export interface SettingsSlice {
  settings: Settings
  setSetting: <K extends keyof Settings>(key: K, value: Settings[K]) => void
  resetSettings: () => void
}

export const createSettingsSlice: SliceCreator<SettingsSlice> = (set, get) => ({
  settings: DEFAULT_SETTINGS,
  setSetting: (key, value) => {
    const next = { ...get().settings, [key]: value }
    set({ settings: next })
    if (key === 'simulateErrors') configureMock({ simulateErrors: next.simulateErrors })
  },
  resetSettings: () => {
    set({ settings: DEFAULT_SETTINGS })
    configureMock({ simulateErrors: DEFAULT_SETTINGS.simulateErrors })
  },
})
