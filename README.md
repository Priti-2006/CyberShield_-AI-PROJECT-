# CyberShield AI

An AI-powered cybersecurity threat analysis dashboard built for the Microsoft Agents League Hackathon.

## Features

- **Email Threat Analysis** — Paste suspicious email content to detect phishing, malware, and impersonation attempts
- **URL Scanner** — Analyze suspicious URLs for malicious indicators and reputation risks
- **Risk Score Engine** — Real-time 0–100 risk scoring with color-coded severity levels
- **Threat Results Panel** — Detailed breakdown of indicators of compromise with actionable recommendations
- **Multi-Agent AI Activity** — Live view of specialized AI agents (Sentinel-Lex, URL-Recon, Phish-GPT, PolicyBot) working in parallel
- **Threat History** — Persistent log of all past scans with timestamps, scores, and quick actions
- **Report Export** — Download threat analysis reports as `.txt` files for documentation and sharing

## Tech Stack

- **React 19** — UI framework
- **TanStack Start** — Full-stack React framework with SSR/SSG
- **TanStack Router** — File-based routing with type-safe navigation
- **Tailwind CSS v4** — Utility-first styling
- **shadcn/ui** — Modern accessible UI components
- **TypeScript** — Type-safe development

## Getting Started

### Prerequisites

- [Bun](https://bun.sh/) (recommended) or Node.js 20+

### Install dependencies

```bash
bun install
```

### Run the development server

```bash
bun dev
```

The app will be available at `http://localhost:3000`.

### Build for production

```bash
bun run build
```

## Project Structure

```
src/
  routes/
    index.tsx          # Main dashboard page
  components/
    ui/                # shadcn/ui components (buttons, cards, tables, etc.)
  styles.css           # Global styles with custom cyber theme tokens
  router.tsx           # TanStack Router configuration
```

## Theme

Dark cybersecurity dashboard with:
- Deep navy/black backgrounds
- Purple and blue gradient accents
- Glassmorphism card styling
- Animated scan-line and glow effects
- Real-time status indicators

## Author

Priti Ranjit
