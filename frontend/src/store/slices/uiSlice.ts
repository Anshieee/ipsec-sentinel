import type { Notification } from '@/types/misc'
import type { SliceCreator } from '../types'

export type ReportTab = 'executive' | 'technical'

export interface PrintJob {
  active: boolean
  kind: ReportTab
  markdown: string
}

export interface UiSlice {
  sidebarCollapsed: boolean
  reportOpen: boolean
  reportTab: ReportTab
  helpOpen: boolean
  highlightId?: string
  searchQuery: string
  notifications: Notification[]
  printJob: PrintJob
  toggleSidebar: () => void
  setSidebarCollapsed: (collapsed: boolean) => void
  setReportOpen: (open: boolean) => void
  setReportTab: (tab: ReportTab) => void
  setHelpOpen: (open: boolean) => void
  setHighlightId: (id?: string) => void
  setSearchQuery: (query: string) => void
  setPrintJob: (job: PrintJob) => void
  notify: (notification: { severity: Notification['severity']; message: string }) => void
  markAllRead: () => void
  clearNotifications: () => void
  resetDemoData: () => void
}

let notificationCounter = 0
const MAX_NOTIFICATIONS = 30

export const createUiSlice: SliceCreator<UiSlice> = (set) => ({
  sidebarCollapsed: false,
  reportOpen: false,
  reportTab: 'executive',
  helpOpen: false,
  highlightId: undefined,
  searchQuery: '',
  notifications: [],
  printJob: { active: false, kind: 'executive', markdown: '' },
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
  setReportOpen: (open) => set({ reportOpen: open }),
  setReportTab: (tab) => set({ reportTab: tab }),
  setHelpOpen: (open) => set({ helpOpen: open }),
  setHighlightId: (id) => set({ highlightId: id }),
  setSearchQuery: (query) => set({ searchQuery: query }),
  setPrintJob: (job) => set({ printJob: job }),
  notify: ({ severity, message }) => {
    notificationCounter += 1
    const notification: Notification = {
      id: `n-${notificationCounter}`,
      severity,
      message,
      at: new Date().toISOString(),
      read: false,
    }
    set((state) => ({ notifications: [notification, ...state.notifications].slice(0, MAX_NOTIFICATIONS) }))
  },
  markAllRead: () => set((state) => ({ notifications: state.notifications.map((n) => ({ ...n, read: true })) })),
  clearNotifications: () => set({ notifications: [] }),
  resetDemoData: () =>
    set((state) => ({
      current: null,
      previousRiskScore: undefined,
      status: 'idle',
      error: undefined,
      notifications: [],
      highlightId: undefined,
      searchQuery: '',
      reportOpen: false,
      helpOpen: false,
      printJob: { active: false, kind: 'executive', markdown: '' },
      upload: { status: 'idle', progress: 0 },
      live: {
        ...state.live,
        status: 'idle',
        elapsedSec: 0,
        counters: { packets: 0, ike: 0, esp: 0, ah: 0, other: 0 },
        recent: [],
        handshake: [],
        findings: [],
        revealed: {},
        classes: null,
        working: null,
      },
    })),
})
