# ADR-004: SOC Design System & Analyst UX Direction

## Status
Accepted

## Context
Security analysts spend long shifts monitoring dashboards. Standard marketing-style dashboards with oversized cards, bright gradients, glassmorphism, and excessive animations cause visual fatigue and lower information density.

## Decision
We implement a **Restrained, Professional SOC Design System**:
1. **Palette**: Dark/neutral foundations with high contrast, subdued borders, and strict semantic severity colors:
   - Critical: `#EF4444` (Crimson / Red-500)
   - High: `#F97316` (Amber / Orange-500)
   - Medium: `#F59E0B` (Yellow / Amber-500)
   - Low: `#3B82F6` (Blue-500)
   - Info: `#64748B` (Slate-500)
2. **Typography**: Monospace font for security hashes, IP addresses, and Incident IDs (`INC-XXXX`); clean sans-serif for UI labels.
3. **Information Density**: Compact rows, clear table layouts, and minimal decoration.
4. **State Handling**: Explicit components for loading skeletons, empty queues, server errors, and 403 forbidden access.

## Consequences
- **Positive**: High readability, low cognitive load, fast threat triage for analysts.
- **Negative**: Avoids flashy visual trends in favor of utilitarian enterprise ergonomics.
