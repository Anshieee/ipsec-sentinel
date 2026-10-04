import React from 'react'
import ReactDOM from 'react-dom/client'
// Self-hosted, bundled fonts (Geist + Geist Mono, OFL licence —
// same families as the reference app; see docs/theme-reference.md).
// Nothing is fetched from a CDN at runtime.
import '@fontsource/geist'
import '@fontsource/geist-mono'
import App from './App'
import './styles/index.css'
import './styles/print.css'

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('Root element #root is missing from index.html')
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
