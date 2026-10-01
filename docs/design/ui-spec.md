# UI Specification

## Color Palette (Severity-Based)

### Primary Colors
- **Deep Blue** (#1e3a8a) — Primary actions, navigation, confidence scores
- **Midnight Green** (#065f46) — Success states, security assessments
- **Crimson** (#dc2626) — Errors, high severity findings
- **Amber** (#d97706) — Warnings, medium severity
- **Slate Gray** (#475569) — Neutral text, secondary information
- **White** (#ffffff) — Backgrounds, main content areas
- ** charcoal** (#1e293b) — Secondary backgrounds, text on light elements

### Semantic Colors (Color Variables)
```css
:root {
  --color-primary: #1e3a8a;
  --color-primary-dark: #1e293b;
  --color-success: #065f46;
  --color-warning: #d97706;
  --color-error: #dc2626;
  --color-info: #475569;
  --color-bg-main: #ffffff;
  --color-bg-secondary: #f8fafc;
  --color-text-primary: #1e293b;
  --color-text-secondary: #475569;
  --color-border: #e2e8f0;
}

/* Severity variants */
.severity-critical { color: var(--color-error); background: #fef2f2; border-color: #fee2e2; }
.severity-high { color: var(--color-warning); background: #fffbeb; border-color: #fed7aa; }
.severity-medium { color: var(--color-warning); background: #fffbeb; border-color: #fed7aa; }
.severity-low { color: var(--color-success); background: #f0fdf4; border-color: #bbf7d0; }
.severity-info { color: var(--color-info); background: #f1f5f9; border-color: #e2e8f0; }
```

## Component Library

### 1. Classification Card
```css
.classification-card {
  background: var(--color-bg-main);
  border: 1px solid var(--color-border);
  border-radius: 8px;
  padding: 20px;
  margin: 10px 0;
}

.field {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin: 12px 0;
}

.field-label {
  font-weight: 600;
  color: var(--color-text-primary);
}

.field-value {
  font-family: 'Roboto Mono', monospace;
  font-weight: 500;
}

.confidence-bar {
  width: 100%;
  height: 8px;
  background: #e2e8f0;
  border-radius: 4px;
  margin: 4px 0;
  overflow: hidden;
}

.confidence-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--color-success), var(--color-warning), var(--color-error));
  border-radius: 4px;
}
```

### 2. Security Score Gauge
```css
.gauge-container {
  position: relative;
  width: 200px;
  height: 200px;
}

.gauge {
  width: 100%;
  height: 100%;
}

.gauge-center {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  text-align: center;
}

.gauge-score {
  font-size: 2.5em;
  font-weight: bold;
  fill: var(--color-primary);
}

.gauge-label {
  font-size: 0.9em;
  fill: var(--color-text-secondary);
}
```

### 3. Threat Matrix
```css
.threat-matrix {
  width: 100%;
  border-collapse: collapse;
  margin: 20px 0;
}

.threat-matrix th,
.threat-matrix td {
  border: 1px solid var(--color-border);
  padding: 12px;
  text-align: center;
  min-width: 120px;
}

.threat-matrix th {
  background: var(--color-bg-secondary);
  font-weight: 600;
}

.threat-matrix td.severity-critical {
  background: rgba(220, 38, 38, 0.1);
  font-weight: bold;
}

.threat-matrix td.severity-high {
  background: rgba(217, 119, 6, 0.1);
}

.threat-matrix td.severity-medium {
  background: rgba(245, 158, 11, 0.1);
}

.threat-matrix td.severity-low {
  background: rgba(6, 95, 70, 0.1);
}
```

### 4. Findings Table
```css
.findings-table {
  width: 100%;
  border-collapse: collapse;
  margin: 20px 0;
}

.findings-table th,
.findings-table td {
  border-bottom: 1px solid var(--color-border);
  padding: 12px;
  text-align: left;
}

.findings-table th {
  background: var(--color-bg-secondary);
  font-weight: 600;
}

.finding-row {
  transition: background 0.2s;
}

.finding-row:hover {
  background: var(--color-bg-secondary);
}

.finding-score {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 4px;
  font-weight: 600;
  font-size: 0.9em;
}
```

### 5. Upload Zone
```css
.upload-zone {
  border: 2px dashed var(--color-border);
  border-radius: 8px;
  padding: 40px;
  text-align: center;
  transition: all 0.3s ease;
  background: var(--color-bg-secondary);
}

.upload-zone.drag-over {
  border-color: var(--color-primary);
  background: rgba(30, 58, 138, 0.05);
}

.upload-zone input[type="file"] {
  display: none;
}

.upload-zone label {
  display: inline-block;
  padding: 12px 24px;
  background: var(--color-primary);
  color: white;
  border-radius: 4px;
  cursor: pointer;
  transition: background 0.2s;
}

.upload-zone label:hover {
  background: var(--color-primary-dark);
}
```

### 6. Navigation
```css
.navigation {
  display: flex;
  justify-content: space-around;
  background: var(--color-bg-secondary);
  padding: 12px;
  border-radius: 8px;
  margin: 20px 0;
}

.nav-item {
  flex: 1;
  text-align: center;
  padding: 12px;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
  color: var(--color-text-secondary);
}

.nav-item:hover {
  background: var(--color-bg-main);
  color: var(--color-primary);
}

.nav-item.active {
  background: var(--color-primary);
  color: white;
}
```

### 7. Charts
```css
.chart-container {
  background: var(--color-bg-main);
  border: 1px solid var(--color-border);
  border-radius: 8px;
  padding: 20px;
  margin: 20px 0;
}

.chart-title {
  font-size: 1.2em;
  font-weight: 600;
  color: var(--color-text-primary);
  margin-bottom: 15px;
}
```

### 8. Report Actions
```css
.report-actions {
  display: flex;
  gap: 12px;
  margin: 20px 0;
}

.btn {
  padding: 12px 24px;
  border: none;
  border-radius: 4px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background: var(--color-primary);
  color: white;
}

.btn-primary:hover {
  background: var(--color-primary-dark);
  transform: translateY(-2px);
}

.btn-secondary {
  background: var(--color-bg-secondary);
  color: var(--color-text-primary);
  border: 1px solid var(--color-border);
}

.btn-secondary:hover {
  background: var(--color-border);
}
```

## JSON Field Mapping

### API Response Schema
```json
{
  "protocol": {
    "field": "protocol",
    "selector": ".classification-card .field-value",
    "type": "text",
    "color": "--color-primary"
  },
  "ike_version": {
    "field": "ike_version", 
    "selector": ".classification-card .field-value",
    "type": "text",
    "color": "--color-success"
  },
  "mode": {
    "field": "mode",
    "selector": ".classification-card .field-value", 
    "type": "text",
    "color": "--color-warning"
  },
  "encryption": {
    "field": "encryption",
    "selector": ".classification-card .field-value",
    "type": "text",
    "color": "--color-error"
  },
  "integrity": {
    "field": "integrity",
    "selector": ".classification-card .field-value",
    "type": "text",
    "color": "--color-warning"
  },
  "dh_group": {
    "field": "dh_group",
    "selector": ".classification-card .field-value",
    "type": "text",
    "color": "--color-info"
  },
  "pfs": {
    "field": "pfs",
    "selector": ".classification-card .field-value",
    "type": "boolean",
    "color": "--color-success"
  },
  "ip_version": {
    "field": "ip_version",
    "selector": ".classification-card .field-value",
    "type": "text",
    "color": "--color-primary"
  },
  "traffic_type": {
    "field": "traffic_type",
    "selector": ".classification-card .field-value",
    "type": "text",
    "color": "--color-warning"
  },
  "ai_confidence": {
    "field": "ai_confidence",
    "selector": ".overall-confidence",
    "type": "percentage",
    "color": "--color-success"
  },
  "security_score": {
    "field": "security_score",
    "selector": ".gauge-score",
    "type": "number",
    "color": "--color-success"
  },
  "threat_matrix": {
    "field": "threat_matrix",
    "selector": ".threat-matrix",
    "type": "matrix",
    "color": "--color-error"
  },
  "findings": {
    "field": ".finding-row",
    "selector": ".findings-table",
    "type": "array",
    "color": "--color-warning"
  },
  "traffic_chart": {
    "field": "#trafficChart",
    "selector": ".chart-container",
    "type": "chart",
    "color": "--color-primary"
  },
  "security_findings": {
    "field": ".finding-score",
    "selector": ".findings-table",
    "type": "object",
    "color": "--color-error"
  }
}
```

## Typography

### Font Stack
```css
@font-face {
  font-family: 'Inter Display';
  src: url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
}

@font-face {
  font-family: 'JetBrains Mono';
  src: url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
}

/* Typography scale */
.h1 { font-size: 2.5rem; font-weight: 700; line-height: 1.2; }
.h2 { font-size: 2rem; font-weight: 600; line-height: 1.3; }
.h3 { font-size: 1.5rem; font-weight: 600; line-height: 1.4; }
.body { font-size: 1rem; font-weight: 400; line-height: 1.6; }
.small { font-size: 0.875rem; font-weight: 400; line-height: 1.5; }
.caption { font-size: 0.75rem; font-weight: 300; line-height: 1.4; }

/* Code and technical elements */
code, pre { font-family: 'JetBrains Mono', monospace; }
```

## Component States

### Upload Zone States
```css
.upload-zone {
  /* Default state */
  border-color: var(--color-border);
  background: var(--color-bg-secondary);
}

.upload-zone.drag-over {
  /* Active state */
  border-color: var(--color-primary);
  background: rgba(30, 58, 138, 0.05);
}

.upload-zone.uploading {
  /* Processing state */
  border-color: var(--color-warning);
  background: rgba(217, 119, 6, 0.05);
}

.upload-zone.success {
  /* Success state */
  border-color: var(--color-success);
  background: rgba(6, 95, 70, 0.05);
}

.upload-zone.error {
  /* Error state */
  border-color: var(--color-error);
  background: rgba(220, 38, 38, 0.05);
}
```

### Card Hover States
```css
.card {
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.card:hover {
  transform: translateY(-4px);
  box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
  border-color: var(--color-primary);
}

.card:active {
  transform: translateY(-2px);
  box-shadow: 0 5px 15px rgba(0, 0, 0, 0.15);
}
```

## Accessibility

### Contrast Ratios
- Primary text on background: 4.5:1 (WCAG AA)
- Success indicators: 3:1 (WCAG AA)
- Error indicators: 3:1 (WCAG AA)

### Focus States
```css
*:focus {
  outline: 2px solid var(--color-primary);
  outline-offset: 2px;
}

button:focus,
input:focus,
a:focus {
  outline: none;
  box-shadow: 0 0 0 3px rgba(30, 58, 138, 0.1);
}
```

## Animation & Motion

### Transition Speeds
```css
:root {
  --transition-fast: 150ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-normal: 300ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-slow: 500ms cubic-bezier(0.4, 0, 0.2, 1);
}
```

### Keyframes
```css
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

@keyframes slideIn {
  from { transform: translateX(-20px); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}

@keyframes shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}
```

## Component Documentation

### Upload Component
- **Purpose**: Accept PCAP files for analysis
- **States**: Default, Drag-over, Uploading, Success, Error
- **Events**: dragover/dragleave, change
- **Validation**: File type (pcap, cap, dmp), size limits

### Classification Component  
- **Purpose**: Display extracted classification results
- **Data**: Protocol, Mode, Encryption, Integrity, DH Group, PFS, IP Version, Traffic Type
- **Visual**: Confidence bars with gradient coloring
- **Responsive**: Adapts to screen size

### Security Assessment Component
- **Purpose**: Display security scoring and threat analysis
- **Data**: Security Score (0-100), Risk Level, Threat Matrix (4x4), Findings list
- **Visual**: Gauge chart for security score, color-coded matrix
- **Interactions**: Clickable findings for details

### Traffic Analysis Component
- **Purpose**: Visual traffic pattern analysis
- **Data**: Packet size distribution, inter-arrival timing, traffic type inference
- **Visual**: Multiple chart types (histogram, line graph)
- **Interactive**: Zoomable, selectable time ranges

### Reports Component
- **Purpose**: Access and download generated reports
- **Data**: Expected solutions, remediation steps
- **Actions**: Download executive/technical reports
- **Interactive**: Expandable solution details