# HoneyMap

> **Autonomous Cyber Deception Grid, Real-Time Intrusion Feed & Honeytoken Forensics Platform**  
> Built with FastAPI, ASGI Python-SocketIO, Async SQLite (WAL), React, TypeScript, Tailwind CSS, and Recharts.

---

## Table of Contents
- [1. Project Overview](#1-project-overview)
- [2. Features](#2-features)
- [3. Technologies Used](#3-technologies-used)
- [4. AI Tools / Models Used and Their Purpose](#4-ai-tools--models-used-and-their-purpose)
- [5. Setup & Installation](#5-setup--installation)
- [6. Usage](#6-usage)
- [7. Project Structure](#7-project-structure)
- [8. Demo — Test Cases for a Judge / Mentor](#8-demo--test-cases-for-a-judge--mentor)
- [9. Any Other Important Information](#9-any-other-important-information)

---

## 1. Project Overview

HoneyMap is an autonomous cyber deception and intrusion detection platform designed to detect, slow down, and analyze malicious actors the moment they probe your infrastructure. Rather than relying on traditional perimeter firewalls that generate thousands of noisy, ambiguous alerts, HoneyMap deploys dynamic decoy assets—fake administrative portals, sensitive configuration files, and high-value credentials known as **honeytokens**—directly alongside legitimate web services.

Because legitimate end users never search for or touch hidden traps like `/.env`, `/backup.sql`, or administrative login portals, any interaction with these assets is an unambiguous signal of hostile reconnaissance or attack. HoneyMap immediately captures these probes, correlates them into distinct attacker sessions using client fingerprinting and geographical intelligence, and applies non-blocking application-layer tarpitting to exhaust the attacker's scanning tools.

All telemetry streams in real time to a modern, light-themed Security Operations Center (SOC) dashboard. Security analysts and judges can watch attacks materialize on a global map, track the kill-chain progression as an attacker escalates from low-level scanning to critical credential abuse, and generate instant, verifiable forensic reports with **zero false positives**.

---

## 2. Features

HoneyMap delivers an active, defensive deception grid built around these working components:

*   **Decoy Portals & Trap Routes**: Authentic-looking decoy login surfaces (`/admin`, `/wp-admin`, `/login`) and an intelligent catch-all router. GET requests render realistic HTML authentication screens; POST attempts return simulated authentication errors while cataloging attacker credentials and exploit patterns.
*   **Adaptive Decoy File Rotation**: A dynamic pool of 6 high-value decoy traps (`/.env`, `/backup.sql`, `/config.php`, `/.git/config`, `/.aws/credentials`, `/wp-config.php`). The backend continuously serves 4 active decoys while rotating them every ~90 seconds to frustrate automated crawlers and detect pattern shifts.
*   **Dynamic Honeytoken Injection & Payoff**: Ephemeral, unique AWS access keys (`AKIA...`) and database passwords dynamically seeded inside decoy files. When an attacker extracts and attempts to reuse these canary credentials against authentication endpoints (e.g., `/api/v1/auth`), the engine triggers an instant, deterministic **CRITICAL** alert.
*   **Session Correlation & Fingerprinting**: Automatic grouping of inbound probes into unified attacker sessions using IP addresses and `User-Agent` signatures. Tracks request velocity, entry points, progression timelines, and maximum severity over an in-memory LRU cache capped at 500 active sessions.
*   **Threat Scoring with Exponential Decay**: Real-time threat calculation incorporating a 5-minute half-life decay formula:
    $$\text{Score}(t) = \text{Score}_{\text{raw}} \times 0.5^{(\Delta t / 300\text{s})}$$
    Attackers who stop probing automatically drop down the rankings, ensuring the Threat Leaderboard always highlights active, immediate threats.
*   **Defensive Non-Blocking Tarpitting**: Repeat offenders face progressive response delays ($\min(0.2\text{s} \times \text{repeat\_count}, 3.0\text{s})$) powered by asynchronous `await asyncio.sleep()`. This bogs down automated fuzzers and attacker scripts without consuming worker threads or blocking legitimate user traffic.
*   **Real-Time Threat Leaderboard**: Live, ranked display of the most aggressive threat actors, showing decayed threat scores, target counts, attack tactics, and geographic origins.
*   **Interactive SOC Command Dashboard**:
    *   **Global Threat Map**: Leaflet-powered geographic mapping showing active attack origins with pulsing severity-coded indicators and offline fallback coordinates.
    *   **Threat Analytics Chart**: Time-bucketed volume and severity distribution (24h, 7d, 30d, 1y) visualized via Recharts.
    *   **Live Activity Feed**: Sub-second socket stream of incoming intrusion attempts with one-click drill-down into raw headers and payloads.
*   **Forensic Incident Dossiers & Timelines**: Slide-out investigation drawer showing complete kill-chain event sequences and exportable structured JSON incident summaries via `/api/report/{session_id}`.

---

## 3. Technologies Used

The HoneyMap architecture is built on a modern, decoupled asynchronous stack:

### Backend Services (`backend/requirements.txt`)
*   **FastAPI (`>=0.110.0`)**: High-performance asynchronous Python framework providing schema-validated REST APIs, lifespan management, and middleware.
*   **uvicorn (`>=0.28.0`)**: Lightning-fast ASGI production web server.
*   **python-socketio (`>=5.11.0`)**: ASGI-mounted Socket.IO server enabling bi-directional, sub-second event broadcasts.
*   **aiosqlite (`>=0.20.0`)**: Asynchronous SQLite driver configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and a 30-second busy timeout for concurrent read/write transactions.
*   **pydantic (`>=2.6.0`)**: Strict runtime type enforcement and schema definitions for all API responses.
*   **python-dotenv (`>=1.0.0`)**: Environment variable management.
*   **requests (`>=2.31.0`)**: HTTP engine powering the multi-vector attack simulation suite.

### Frontend Application (`frontend/package.json`)
*   **React (`18.3.1`)** & **TypeScript (`5.6.3`)**: Component-driven architecture with strict compile-time type safety.
*   **Vite (`5.3.4`)**: High-speed build tooling and local development server with Hot Module Replacement (HMR).
*   **Tailwind CSS (`3.4.14`)**: Clean, modern light SaaS design system utilizing high-contrast charcoal typography on neutral slate backgrounds.
*   **shadcn/ui & Radix UI Primitives**: Accessible UI building blocks (`@radix-ui/react-dialog`, `@radix-ui/react-tabs`, `@radix-ui/react-tooltip`, `@radix-ui/react-slot`).
*   **Recharts (`2.13.3`)**: Composable SVG charting library for temporal threat distribution.
*   **Leaflet (`1.9.4`)** & **react-leaflet (`4.2.1`)**: Hardware-accelerated interactive map rendering.
*   **Lucide React (`0.454.0`)**: Consistent, modern cybersecurity iconography.
*   **socket.io-client (`4.7.5`)**: Real-time event transport with automatic WebSocket connection management and fallback polling.

---

## 4. AI Tools / Models Used and Their Purpose

### Deterministic Rule-Based Classification (No Black-Box ML)
HoneyMap's threat detection and severity engine is **rule-based and deterministic**, not machine learning. This is an intentional, security-first design choice:
1.  **100% Explainability**: In cybersecurity, black-box ML models produce probabilistic guesses that are difficult to explain to auditors, incident responders, or judges. In HoneyMap, every severity rating is tied to clear, reproducible evidence:
    *   `LOW`: Reconnaissance and directory discovery (e.g., probing `/login` or `/admin`).
    *   `MEDIUM`: Sensitive configuration file hunting (e.g., accessing `/.env` or `/backup.sql`).
    *   `HIGH`: Active exploit payloads (e.g., SQL injection `' OR 1=1 --`, XSS scripts, path traversal).
    *   `CRITICAL`: Verified honeytoken reuse (e.g., attempting authentication with an ephemeral AWS key leaked from a decoy file).
2.  **Zero False Positives**: Traditional security tools trigger false alarms on unusual user behavior. HoneyMap eliminates this: because decoy assets and honeytokens are never advertised to legitimate users, **any interaction is guaranteed malicious**.
3.  **Predictable & Instantaneous**: Rule-based matching executes in sub-millisecond time without GPU dependencies, cold-start latency, or model drift.

### Optional Executive Incident Narrative Hook (Anthropic Claude API)
The backend includes an optional hook in the incident reporting endpoint (`/api/report/{session_id}`):
*   **Purpose**: If an `ANTHROPIC_API_KEY` is configured in the environment, HoneyMap can forward the structured forensic timeline of an attacker to Claude to synthesize a plain-English executive summary suitable for non-technical stakeholders and C-level debriefs.
*   **Core Independence**: This LLM integration is **completely optional**. The entire platform—decoy generation, live map, session tracking, threat scoring, and structured JSON reporting—operates fully offline and does not require an API key to run.

---

## 5. Setup & Installation

### Prerequisites
*   **Python**: Version 3.10 or higher
*   **Node.js**: Version 18 or higher (with `npm`)

### 1. Clone & Configure Environment
Clone the repository and copy the environment template:
```bash
git clone https://github.com/your-username/Honeymap.git
cd Honeymap

# Copy root configuration template
cp .env.example .env
```

#### Environment Variables Reference (`.env.example`)
| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `HONEYMAP_HOST` | `0.0.0.0` | Backend server bind address |
| `HONEYMAP_PORT` | `5000` | Backend server bind port |
| `HONEYMAP_DB_PATH` | `honeymap.db` | Local SQLite database file path |
| `HONEYMAP_RATE_LIMIT_MAX` | `300` | Sliding-window request cap per IP (60s window) |
| `HONEYMAP_GEOIP_TIMEOUT` | `2.0` | Timeout in seconds for live IP geolocation queries |
| `HONEYMAP_CORS_ORIGINS` | `http://localhost:5173` | Allowed CORS origins for REST and WebSockets |
| `VITE_API_BASE` | `http://localhost:5000` | Frontend backend API target URL |
| `VITE_SOCKET_URL` | `http://localhost:5000` | Frontend Socket.IO target URL |

### 2. Backend Installation
```bash
cd backend

# Create and activate virtual environment
python -m venv venv

# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Frontend Installation
```bash
cd ../frontend

# Install frontend dependencies
npm install
```

---

## 6. Usage

To run the complete HoneyMap platform and simulate live cyber attacks, open **three terminal windows**:

### Terminal 1 — Start the FastAPI Backend
```bash
cd backend

# Activate virtual environment
# Windows: .\venv\Scripts\Activate.ps1 | Linux/macOS: source venv/bin/activate

# Start using Python directly:
python app.py

# Or start using Uvicorn ASGI server directly:
uvicorn app:socket_app --host 0.0.0.0 --port 5000
```
*The FastAPI lifespan initializes the async SQLite database in WAL mode, generates active honeytokens, and binds ASGI python-socketio on `http://localhost:5000`.*

### Terminal 2 — Start the React Dashboard
```bash
cd frontend
npm run dev
```
*Vite will compile and launch the dashboard at `http://localhost:5173`. Open this URL in Google Chrome or your browser of choice.*

### Terminal 3 — Run the Multi-Vector Attack Simulator
HoneyMap includes a built-in simulation suite to demonstrate real-time threat detection:

```bash
# Option A: Human-paced scripted attack demonstrating the complete kill-chain (~35-45s)
python backend/simulate_attack.py scripted

# Option B: Fast mode for quick CI/CD verification (~15s)
python backend/simulate_attack.py scripted --fast

# Option C: Background multi-attacker noise simulation (5 concurrent IPs)
python backend/simulate_attack.py noise --duration 120
```

---

## 7. Project Structure

The codebase is organized cleanly into decoupled backend and frontend packages:

```
HoneyMap/
├── .env.example                     # Master environment variables template
├── README.md                        # Documentation & setup guide
│
├── backend/                         # FastAPI & ASGI Services
│   ├── .env.example                 # Backend environment configuration
│   ├── app.py                       # FastAPI application, REST endpoints, CORS & rate limiter
│   ├── database.py                  # Async aiosqlite connection pool & WAL schema setup
│   ├── honeymap.db                  # Local SQLite database (WAL journal mode)
│   ├── requirements.txt             # Python dependencies
│   ├── simulate_attack.py           # Multi-vector attack generator (scripted & noise modes)
│   ├── socket_instance.py           # Async python-socketio instance
│   │
│   ├── decoys/                      # Cyber Deception Routing Layer
│   │   ├── fake_files.py            # Decoy file generation & adaptive rotation logic
│   │   ├── fake_login.py            # Honeypot login surfaces (/admin, /wp-admin, /login)
│   │   ├── logger.py                # Intrusion logger & real-time Socket.IO emitter
│   │   └── request_utils.py         # Client IP resolution & header sanitization
│   │
│   ├── detection/                   # Threat Classification & State
│   │   ├── classifier.py            # 4-tier deterministic rule-based classifier
│   │   ├── geoip.py                 # GeoIP resolution with local offline coordinates
│   │   ├── honeytokens.py           # Ephemeral honeytoken lifecycle & verification registry
│   │   └── session_tracker.py       # Attacker session tracking, LRU cache & score decay
│   │
│   └── test_final_audit.py          # Automated verification test suite
│
└── frontend/                        # React + TypeScript + Tailwind Frontend
    ├── .env.example                 # Frontend environment configuration
    ├── package.json                 # Node.js dependencies & scripts
    ├── tailwind.config.js           # Light SaaS design system theme & tokens
    ├── tsconfig.json                # TypeScript compiler configuration
    ├── vite.config.ts               # Vite bundler configuration
    ├── index.html                   # HTML entry point & typography
    │
    └── src/
        ├── App.tsx                  # Master SOC dashboard shell & view switcher
        ├── main.tsx                 # React application mounting
        ├── index.css                # Global styles, scrollbars & map layers
        │
        ├── api/                     # Backend Transport Layer
        │   ├── client.ts            # Typed REST client with polling fallback
        │   └── socket.ts            # Socket.IO connection manager & reconnect logic
        │
        ├── types/                   # Shared TypeScript Definitions
        │   └── index.ts             # Schemas for events, sessions, metrics & decoys
        │
        ├── lib/                     # Utilities
        │   └── utils.ts             # Tailwind class merging utility (clsx + twMerge)
        │
        └── components/              # SOC UI Components
            ├── TopBar.tsx           # Health indicators, active traps counter, status badge
            ├── Sidebar.tsx          # Navigation sidebar
            ├── MetricsCards.tsx     # KPI summary cards (Critical, Tarpitted, Active, Total)
            ├── ThreatAnalyticsChart.tsx # Volume & severity temporal chart (Recharts)
            ├── ThreatMap.tsx        # Interactive global threat map (Leaflet)
            ├── RecentActivityFeed.tsx # Real-time intrusion stream with severity badges
            ├── Leaderboard.tsx      # Ranked threat actors with live score decay
            ├── IncidentDrawer.tsx   # Slide-out kill-chain timeline & payload viewer
            ├── SystemStatusCards.tsx# Decoy rotation monitor & system health cards
            ├── AttackTargetsTable.tsx # Breakdown of probed endpoints and paths
            ├── ThreatIntelView.tsx  # Honeytoken inventory & compromised token log
            ├── VulnerabilitiesView.tsx # Active decoy attack surface breakdown
            ├── DetectionEngineView.tsx # Classification rulebook & tarpit parameters
            ├── ReportsView.tsx      # Exportable incident dossiers & session reports
            ├── SettingsView.tsx     # Security controls & rate limit configuration
            └── ui/                  # Reusable accessible UI primitives (shadcn/ui)
```

---

## 8. Demo — Test Cases for a Judge / Mentor

Follow this exact 4-step evaluation flow to verify HoneyMap's capabilities firsthand without requiring any complex setup:

### Test 1 — Baseline Check
1.  Launch the backend and frontend following the [Usage](#6-usage) instructions.
2.  Open `http://localhost:5173` in Google Chrome.
3.  **Observation**:
    *   Verify the system status indicator in the top-right displays a green **"Protected"** badge.
    *   Verify the top metric cards display clean baseline metrics: **0** Critical Threats and clean charts.
    *   Verify the Threat Map shows the world map ready to receive telemetry.
    *   *Confirms the platform is healthy, connected via WebSockets, and ready before any intrusion occurs.*

### Test 2 — Live Attack Detection
1.  Keep the browser dashboard visible on your screen.
2.  In a second terminal, start the scripted attack generator:
    ```bash
    python backend/simulate_attack.py scripted
    ```
3.  **Observation**:
    *   Within 1-2 seconds, a marker will immediately appear on the live map in Moscow, Russia (IP: `194.26.29.112`).
    *   A new entry (`/login`) appears instantly at the top of the **Recent Activity Feed** with a blue `LOW` severity badge.
    *   *Confirms real-time push detection works over WebSockets without manual page refreshes.*

### Test 3 — Escalation & the Honeytoken Payoff
1.  Allow the scripted attack to continue running in Terminal 2 (it runs over ~35-45 seconds).
2.  **Observation**:
    *   **Phase 1 (~8s)**: Attacker probes `/admin`. Severity stays `LOW`.
    *   **Phase 2 (~16s)**: Attacker downloads `/.env` and extracts a dynamically generated AWS access key (`AKIA...`). Severity escalates to orange `MEDIUM`.
    *   **Phase 3 (~26s)**: Attacker attempts an SQL injection (`' OR 1=1 --`) on the login form. Severity escalates to purple `HIGH`.
    *   **Phase 4 (~36s)**: Attacker attempts to use the stolen AWS key against `/api/v1/auth`. Severity spikes to red **`CRITICAL`** with reason *"honeytoken reuse detected"*.
    *   Click on the **CRITICAL** event in the Activity Feed or Leaderboard to open the **Incident Drawer**. Inspect the chronological kill-chain timeline showing the attacker's progression from initial reconnaissance to credential abuse.
    *   *This is the strongest proof point: it demonstrates deterministic detection of stolen credentials with zero ambiguity.*

### Test 4 — Multi-Attacker Resilience & Score Decay
1.  While the dashboard is open, launch background traffic simulation:
    ```bash
    python backend/simulate_attack.py noise --duration 60
    ```
2.  **Observation**:
    *   Multiple distinct threat actors (from Germany, China, Ukraine, Brazil, and Vietnam) begin probing various decoy endpoints.
    *   The **Threat Leaderboard** updates in real time, ordering actors by their cumulative threat scores.
    *   As attackers pause or complete their scans, observe their scores undergo **exponential score decay**, allowing active attackers to rise above idle sessions.
    *   *Confirms the platform gracefully handles multiple concurrent adversaries and scales past single toy scenarios.*

---

## 9. Any Other Important Information

### Known Limitations
*   **Single-Node SQLite Storage**: HoneyMap currently uses local asynchronous SQLite with Write-Ahead Logging (WAL) for lightweight, zero-dependency deployment. In an enterprise multi-node deployment, this would be backed by a managed PostgreSQL or CockroachDB cluster.
*   **Application-Layer Tarpitting vs. Kernel Firewall**: HoneyMap implements non-blocking application-layer tarpitting using `await asyncio.sleep()` to slow down hostile crawlers. In a full enterprise deployment, this can be coupled with network-layer blocking via Cloudflare Workers, AWS WAF, or Linux `iptables` hooks.
*   **Optional AI Narrative Hook**: The Anthropic Claude narrative summary hook at `/api/report/{session_id}` is an optional enhancement for generating executive debriefs. HoneyMap's core detection, scoring, and forensics function 100% autonomously without external cloud dependencies.

### Verification Status (Watchdog Protocol)
*   **Decoy Endpoints**: All decoy routes (`/admin`, `/wp-admin`, `/login`, `/.env`, `/backup.sql`, `/config.php`, `/.git/config`, `/.aws/credentials`, `/wp-config.php`) verified functional with adaptive rotation.
*   **Rule Engine**: 4-tier classifier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) verified via comprehensive automated unit tests.
*   **Rate Limiting**: Sliding-window rate limiter (300 req/60s) returning HTTP `429` with `Retry-After` header verified.
*   **Contract Parity**: REST polling fallback and Socket.IO real-time event schemas are verified 100% identical.
*   **Frontend Production Build**: `npm run build` passes with zero TypeScript or bundling errors.

---

### Team & Acknowledgements
Developed with ❤️ as a modern, high-fidelity cyber deception platform. Designed to demonstrate that deceptive defense can turn the asymmetry of cyber warfare back against attackers.
