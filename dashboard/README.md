# Dashboard — vendored frontend snapshot (integration task)

The UI lives in `frontend/` (snapshot, see `frontend/SOURCE.md`; no
dashboard code is built in this repo). Point it at this backend:

```bash
cd frontend && npm ci
VITE_USE_MOCK=false VITE_API_URL=http://127.0.0.1:8000 npm run dev
```

Contract: `docs/frontend-handoff.md`, `docs/api-contract.md`,
`docs/openapi.json`. Mock mode needs no backend
(`ipsec-analyze serve --mock`).
