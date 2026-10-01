import '@testing-library/jest-dom/vitest'

/**
 * Node 26 + jsdom does not expose `window.localStorage` in this environment.
 * The application only needs a Web Storage shaped object for the persisted
 * settings, so a small in-memory stand-in keeps the persistence tests honest.
 * Real browsers always provide their own storage and never hit this branch.
 */
function installInMemoryStorage(): void {
  if (typeof window === 'undefined') return
  const existing = Reflect.get(window, 'localStorage')
  if (existing) return
  const store = new Map<string, string>()
  const storage: Storage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => {
      store.set(key, String(value))
    },
    removeItem: (key: string) => {
      store.delete(key)
    },
    clear: () => {
      store.clear()
    },
    key: (index: number) => Array.from(store.keys())[index] ?? null,
    get length() {
      return store.size
    },
  }
  Object.defineProperty(window, 'localStorage', { value: storage, configurable: true, writable: true })
}

/**
 * jsdom does not implement `ResizeObserver`, which Recharts' `ResponsiveContainer`
 * subscribes to on mount. A minimal stub keeps chart components renderable in
 * tests; real browsers provide the native implementation.
 */
function installResizeObserverStub(): void {
  if (typeof globalThis === 'undefined') return
  if (typeof globalThis.ResizeObserver === 'function') return
  class ResizeObserverStub implements ResizeObserver {
    observe(): void {}
    unobserve(): void {}
    disconnect(): void {}
  }
  Object.defineProperty(globalThis, 'ResizeObserver', {
    value: ResizeObserverStub,
    configurable: true,
    writable: true,
  })
}

/**
 * jsdom logs "Not implemented: navigation" for anchor clicks used by the
 * download helpers; `scrollIntoView` is also unimplemented. Both are no-ops here.
 */
function installDomStubs(): void {
  if (typeof window === 'undefined') return
  if (typeof window.HTMLElement.prototype.scrollIntoView !== 'function') {
    Object.defineProperty(window.HTMLElement.prototype, 'scrollIntoView', {
      value: () => {},
      configurable: true,
      writable: true,
    })
  }
}

installInMemoryStorage()
installResizeObserverStub()
installDomStubs()
