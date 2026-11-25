# The Gateway That Says No — Interactive Demo
Install: `pip install fastapi uvicorn pydantic pyyaml`
Run: `python -m uvicorn demo.server:app --port 8000` -> `http://localhost:8000`
Chapters:
1. Meet the team — 4 roles, Table 3.4 privilege matrix, default-deny architecture
2. A normal day — benign internal e-mail allowed (`ALLOW_COM_EMAIL`)
3. Stepping out of line — static RBAC denies Researcher e-mail (`DENY_RES_EMAIL`)
4. The poisoned web page — indirect prompt injection + taint copies on delegation (`DENY_TAINTED_EXTERNAL_EMAIL`)
5. No laundering through middlemen — two-hop taint propagation via Orchestrator
6. Not a blunt instrument — internal mail allowed; multi-recipient & look-alike domain denied
7. Secrets stay home + A human decides — `CONFIDENTIAL_INTERNAL` + live HITL approval modal
8. The logs cannot lie — SHA-256 hash chain verify, line-2 tamper detection, restore
9. The scoreboard — 20/20 → 0/20 ASR, 95% utility, 6.1/8.0 µs latency, residual risks R1–R3 & N19
