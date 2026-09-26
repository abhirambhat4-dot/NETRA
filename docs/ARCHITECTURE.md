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

### Routes

| Path               | Page                |
|--------------------|---------------------|
| `/login`           | Login               |
| `/`                | Dashboard           |
| `/events`          | Security Events     |
| `/incidents`       | Incidents           |
| `/incidents/:id`   | Incident Details    |
| `/authorization`   | Authorization       |
| `/containment`     | Containment         |
| `/memory`          | Cyber Memory        |
| `/assets`          | Assets              |
| `/threat-intel`    | Threat Intelligence |
| `/settings`        | Settings            |

### Severity colours

| Severity | Colour        |
|----------|---------------|
| CRITICAL | red           |
| HIGH     | orange        |
| MEDIUM   | amber         |
| LOW      | green         |
| INFO     | blue/neutral  |
