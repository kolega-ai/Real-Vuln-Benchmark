# Dashboard Redesign — Design Spec

## Summary

Redesign the RealVuln dashboard to use the Kolega Comply design system and a leaderboard-first layout. Two page types: main dashboard (leaderboard) and scanner detail pages (analytical deep-dive).

## Audience

External security researchers and scanner vendors. Open source, public-facing benchmark.

## Design System

Kolega Comply dark mode tokens:

| Token | Value | Usage |
|-------|-------|-------|
| Background | `#000000` | Page background |
| Cards | `#171717` | Elevated surfaces |
| Tertiary BG | `#262626` | Bar tracks, hover states |
| Text primary | `#FFFFFF` | Headings, body |
| Text secondary | `#B3B3B3` | Labels, descriptions |
| Text tertiary | `#808080` | Captions, hints |
| Text muted | `#666666` | Disabled/placeholder |
| Border primary | `#404040` | Card borders, dividers |
| Border secondary | `#262626` | Subtle separators |
| Accent lime | `#C4F03E` | CTAs, #1 rank highlight |
| Accent lime dark | `#ADDD30` | Primary buttons |
| Accent purple | `#7E22CE` | Special highlights |
| Accent purple light | `#A076F9` | Info accent |

Typography:
- Headings: Space Grotesk (bold/semibold)
- Body: Inter (regular/medium)
- Code/repo names: Source Code Pro

Border radius: `rounded-2xl` (16px) cards, `rounded-lg` (8px) buttons/inputs, `rounded-md` (6px) badges/heatmap cells.

Score colors: `#22c55e` (great 80+), `#84cc16` (good 60+), `#eab308` (ok 40+), `#f97316` (poor 20+), `#ef4444` (bad 0-19).

## Main Dashboard — Sections (top to bottom)

### 1. Header
- Title: "RealVuln Benchmark" (Space Grotesk, 28px, bold)
- Badge: "Open Source" (lime bg, black text, rounded-md)
- Subtitle: one-liner description (Inter, 14px, text-secondary)
- No kolega.dev branding in header

### 2. Hero Stats (4 cards, grid)
- Vulnerabilities (698, red icon)
- FP Traps (125, yellow icon)
- Repositories (27, purple icon)
- Scanners Tested (N, lime icon)
- Card pattern: icon (40x40 rounded-lg with 10% tinted bg) + value + label

### 3. Scanner Leaderboard
- Ranked rows, each a card (bg-secondary, border-secondary, rounded-2xl)
- Row contents: rank number, scanner name (Space Grotesk), F2 bar (gradient fill), F2 score (large, color-coded), recall/precision inline text, chevron arrow
- #1 row: lime border highlight, lime rank number
- Hover: border-primary, hover-bg, shadow-lg, arrow turns lime
- Click navigates to scanner detail page

### 4. Precision vs Recall Scatter
- Plotly chart in a card container (bg-secondary, rounded-2xl)
- One dot per scanner, labeled, color-coded
- F2 iso-curve lines (dashed, labeled F2=20/30/40/50/60/80)
- Click dot to navigate to scanner detail
- Plotly theme: bg=`#171717`, grid=`#262626`, text=`#B3B3B3`

### 5. TP/FP/FN Finding Breakdown
- Horizontal stacked bars per scanner
- Legend: green=TP, red=FP, orange=FN
- Raw counts shown to the right of each bar

### 6. CWE Detection Coverage (NEW)
- Card grid (auto-fill, minmax 200px)
- Each card: CWE family name, "X/N scanners detect, Y% avg recall", thin progress bar
- Data: aggregate per-family recall across all scanners from scorecard data

### 7. Per-Repository Heatmap
- Wrapped in card container (bg-secondary, rounded-2xl)
- Table: repos (rows) x scanners (cols), F2 cells with rounded badges
- Color scale: great/good/ok/poor/bad/none
- Sortable columns, hover rows
- Metric toggle (F2/Recall/Precision) retained

### 8. Footer
- `kolega.dev` link, GitHub link, Methodology link, generation timestamp

## Scanner Detail Pages (click-through)

Structure unchanged, restyled to match:
1. Back link to dashboard
2. Scanner name as title (Space Grotesk)
3. KPI cards: Micro F2, Recall, Precision, Repos Scored
4. Per-repo TP/FP/FN bar chart (Plotly)
5. Per-repo scores table (sortable, metric toggle)
6. Severity breakdown (cards + chart)
7. CWE Family heatmap (recall by repo x family)
8. CWE Family aggregate bar chart

## Technical Approach

- Modify `dashboard.py` — update `_common_css()`, `build_html()`, `build_scanner_detail_html()`
- Add Google Fonts link (Space Grotesk, Inter, Source Code Pro) to HTML head
- New leaderboard HTML section replaces scanner-directory cards
- CWE Coverage section: compute aggregate per-family stats in `build_html()`
- Keep Plotly for scatter/bars, restyle with new theme colors
- TP/FP/FN bars: can be pure HTML/CSS (no Plotly needed)
- Retain all existing interactivity: metric toggle, column sorting, tooltips, click-through navigation

## Mockup Reference

`.superpowers/brainstorm/19569-1773125930/dashboard-mockup-v3.html`
