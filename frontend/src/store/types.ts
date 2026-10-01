import type { StateCreator } from 'zustand'
import type { AnalysisSlice } from './slices/analysisSlice'
import type { UploadSlice } from './slices/uploadSlice'
import type { LiveSlice } from './slices/liveSlice'
import type { UiSlice } from './slices/uiSlice'
import type { SettingsSlice } from './slices/settingsSlice'

export type SentinelState = AnalysisSlice & UploadSlice & LiveSlice & UiSlice & SettingsSlice

export type SliceCreator<T> = StateCreator<SentinelState, [], [], T>
