import React from 'react'
import ReactDOM from 'react-dom/client'
// Self-hosted, bundled fonts (approved font exception, see DESIGN_DECISIONS.md D2).
// Nothing is fetched from a CDN at runtime.
import '@fontsource-variable/ibm-plex-sans'
import '@fontsource-variable/jetbrains-mono'
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
