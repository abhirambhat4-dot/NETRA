# NETRA Architecture

## 1. Workflow

```
Detect ──▶ Understand ──▶ Prioritise ──▶ Verify ──▶ Contain ──▶ Learn
Suricata    Correlate       Risk score     Human       Block /     Cyber
+ ML        events into     + explanation  approval    isolate     Memory
            incidents       + decision     + OTP       + verify
```

## 2. Components

```
┌─────────────┐   ┌─────────────┐   ┌──────────────┐
│  suricata/  │──▶│ collector/  │──▶│  detection/  │  (scikit-learn anomaly)
└─────────────┘   └─────────────┘   └──────┬───────┘
                                           ▼
                  ┌─────────────┐   ┌──────────────┐
                  │  database/  │◀─▶│   backend/   │  FastAPI
                  │ PostgreSQL  │   │  REST /api   │
                  └─────────────┘   └──────┬───────┘
                                           ▼ JSON
                                    ┌──────────────┐
                                    │  frontend/   │  React SOC UI
                                    └──────────────┘
```

## 3. Data model (entity chain)

```
SecurityEvent ──(incidentId)──▶ Incident ──(assetId)──▶ Asset
                                   │
                                   ├──▶ RiskAssessment   (score, novelty, confidence, CVSS, factors, explanation)
                                   ├──▶ Decision         (recommended containment action)
                                   ├──▶ Authorization    (approver + OTP)
                                   ├──▶ ContainmentAction(execute + verify)
                                   └──▶ CyberMemoryEntry (outcome + lessons learned)
```

All types are defined in **`frontend/src/api/types.ts`** — this is the contract.

### Conventions
- JSON keys: **camelCase** (backend: Pydantic `alias_generator=to_camel`, `populate_by_name=True`).
- Timestamps: ISO-8601 UTC strings.
- IDs: prefixed strings — `EVT-`, `INC-`, `AST-`, `RSK-`, `DEC-`, `AUT-`, `CNT-`, `MEM-`.
- `riskScore` 0–100; `novelty`, `confidence`, `anomalyScore` 0–1; `cvss` 0–10.
- Enums are UPPER_SNAKE_CASE strings.
- Errors: FastAPI default `{ "detail": "message" }`.
- Lists: `PaginatedResponse<T>` = `{ items, total, page, pageSize }`.
- Auth: `Authorization: Bearer <accessToken>`.

## 4. REST API (planned, base `/api/v1`)

| Method | Path                                   | Returns                          |
|--------|----------------------------------------|----------------------------------|
| POST   | `/auth/login`                          | `LoginResponse`                  |
| GET    | `/auth/me`                             | `User`                           |
| GET    | `/dashboard/stats`                     | `DashboardStats`                 |
| GET    | `/dashboard/risk-trend?range=24h\|7d`   | `RiskTrendPoint[]`               |
| GET    | `/system/health`                       | `SystemComponentHealth[]`        |
| GET    | `/events`                              | `PaginatedResponse<SecurityEvent>` (query: `SecurityEventFilters`) |
| GET    | `/events/{id}`                         | `SecurityEvent`                  |
| GET    | `/incidents`                           | `PaginatedResponse<Incident>` (query: `IncidentFilters`) |
| GET    | `/incidents/{id}`                      | `IncidentDetail`                 |
| POST   | `/incidents/{id}/authorization`        | `Authorization` (request approval) |
| POST   | `/authorizations/{id}/otp/verify`      | `Authorization` (body: `OtpVerifyRequest`) |
| POST   | `/authorizations/{id}/reject`          | `Authorization`                  |
| POST   | `/containment/{id}/execute`            | `ContainmentAction`              |
| POST   | `/containment/{id}/verify`             | `ContainmentAction`              |
| GET    | `/assets`                              | `Asset[]`                        |
| GET    | `/assets/{id}`                         | `Asset`                          |
| GET    | `/threat-intel/techniques`             | `MitreTechnique[]`               |
| GET    | `/threat-intel/observed`               | `TechniqueObservation[]`         |
| GET    | `/threat-intel/indicators`             | `ThreatIndicator[]`              |
| GET    | `/memory`                              | `CyberMemoryEntry[]`             |
| GET    | `/memory/{id}`                         | `CyberMemoryEntry`               |

## 5. Frontend architecture

```
pages/  ──▶ hooks/ ──▶ services/ ──▶ mocks/       (now)
                              └────▶ fetch /api   (later, same signatures)
```

- **Pages never import mock data directly** — only via `services/`.
- Each service function returns `Promise<T>` of a contract type, so swapping mock → FastAPI changes only `services/`.
- Toggle via `VITE_USE_MOCKS=true|false` and `VITE_API_BASE_URL`.

### Mock world (`frontend/src/mocks/`)

| File           | Role                                                                 |
|----------------|----------------------------------------------------------------------|
| `scenarios.ts` | Incident narratives: events, risk inputs, decision → authorization → containment → memory |
| `assets.ts`    | Asset inventory (criticality, exposure, CVEs)                        |
| `mitre.ts`     | ATT&CK techniques                                                    |
| `intel.ts`     | Threat indicators (safe RFC 5737 / `.example` values) linked to incidents |
| `db.ts`        | Derives every record + aggregate from the above (risk scores, trends, dashboard stats) |
| `api.ts`       | Mock endpoint implementations with simulated latency                 |

Workflow actions (request authorization → OTP approve/reject → execute → verify → memory)
are simulated in `db.ts` (`db.actions`). The demo OTP is `246810`. After any mutation the
service layer dispatches `netra:data-changed`, and every `useQuery` refetches, so the
dashboard, sidebar badge and lists stay consistent. A page reload resets the demo.

Risk model used by the mock (backend should match): weighted factors —
asset criticality 25%, vulnerability CVSS 20%, behavioural novelty 20%,
detection confidence 15%, ATT&CK technique 10%, threat intel 10%.
System risk = 40 + 60 × (1 − Π(1 − 0.17 × riskᵢ/100)) over active incidents.

### Routes

| Path                   | Page                                          |
|------------------------|-----------------------------------------------|
| `/login`               | Login                                         |
| `/dashboard`           | Command Center (`/` redirects here)           |
| `/events`              | Security Events                               |
| `/incidents`           | Incidents                                     |
| `/incidents/:id`       | Incident Details                              |
| `/assets`              | Assets                                        |
| `/threat-intelligence` | Threat Intelligence                           |
| `/cyber-memory`        | Cyber Memory                                  |
| `/settings`            | Settings                                      |
| `/design-system`       | Internal component reference (not in nav)     |

### Severity colours

| Severity | Colour        |
|----------|---------------|
| CRITICAL | red           |
| HIGH     | orange        |
| MEDIUM   | amber         |
| LOW      | green         |
| INFO     | blue/neutral  |
