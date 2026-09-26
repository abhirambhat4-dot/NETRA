# NETRA

**A Cyber Decision Intelligence Platform for Collaborative Risk Prioritisation and Security Decision Support.**

NETRA turns raw network detections into prioritised, explainable, human-authorised security decisions:

**Detect → Understand → Prioritise → Verify → Contain → Learn**

## Repository layout

| Folder       | Owner          | Status      | Purpose                                             |
|--------------|----------------|-------------|-----------------------------------------------------|
| `frontend/`  | Frontend       | In progress | React SOC dashboard (mock data until API is ready)  |
| `backend/`   | Backend        | Planned     | FastAPI REST API                                    |
| `database/`  | Backend        | Planned     | PostgreSQL schema & migrations                      |
| `collector/` | Detection      | Planned     | Log/traffic collection                              |
| `suricata/`  | Detection      | Planned     | Suricata IDS rules & config                         |
| `detection/` | Detection      | Planned     | scikit-learn anomaly detection                      |
| `docs/`      | All            | Active      | Architecture & API contract                         |

## Quick start (frontend)

```bash
cd frontend
npm install
npm run dev
```

## Integration

The frontend ↔ backend contract lives in [`frontend/src/api/types.ts`](frontend/src/api/types.ts).
Endpoints and conventions are documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
