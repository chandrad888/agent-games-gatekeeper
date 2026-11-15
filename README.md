# Proof Gatekeeper Agent — zkVerify Agent Games (Season 01)

A competition-ready **Proof Gatekeeper** agent: an HTTPS JSON endpoint that
judges proof-backed payment tasks (APPROVE / REJECT), and attaches a local
**Groth16 zero-knowledge proof** of each decision, generated with snarkjs and
the official gatekeeper circuit. The circuit enforces that the decision
matches the rules — a wrong decision cannot be proven.

- Track: Proof Gatekeeper · 100,000 VFY per track (50k / 30k / 20k)
- Rounds: 8 daily rounds, 13–20 Nov 2026, 17:30–03:30 WIB, 8 tasks per round
- Deadline per task: 60 seconds (this agent answers in ~0.5 s)
- Full protocol notes and evidence: see **STATUS.md**

## Endpoints

| Route | What |
|---|---|
| `POST /gatekeeper` | Task envelopes and preflight (also accepts `POST /`) |
| `GET /health` | `{ ok, gatekeeper: { hmacConfigured, taskIdMode, selfTest, ... } }` |
| `GET /` | Service info |

Every POST is verified with **HMAC-SHA256 over the raw body**
(`x-agent-games-signature` header, lowercase hex) before parsing; every task
and preflight response is signed the same way. Preflight
`{"type":"agent-games.preflight.v1"}` is answered
`{ok:true, protocolVersion:"v1"}`.

## Quick start (local)

```bash
npm install
cp .env.example .env        # fill AGENT_GAMES_HMAC_SECRET for live use
node server.js              # listens on $PORT (default 8080)

node test/harness.js        # 13 decision+proof cases vs the circuit
node test/preflight-sim.js  # end-to-end platform simulation (dummy secret)
```

Node 22+ required. Only runtime dependency: `snarkjs@0.7.6`
(keccak-256 uses Node's built-in crypto).

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `PORT` | no (8080) | Listen port; hosts inject it automatically |
| `AGENT_GAMES_HMAC_SECRET` | **yes, live** | From the dashboard: your agent → **Rotate Secret**. Without it, inbound verification is disabled and the platform preflight fails |
| `AGENT_GAMES_HMAC_FORMAT` | no (`hex`) | `hex` or `sha256=` — switch only if the platform rejects the preflight |
| `GATEKEEPER_TASK_ID_MODE` | no (`keccak`) | `task_id` → circuit field element: `keccak` (default), `numeric`, `hex`. Switch only if a practice-task proof is rejected |
| `SEEN_STORE_PATH` | no (`./data/seen.json`) | Persistence for the proof_tx seen-set (reuse detection) |

## How a task is decided

First failing check wins (boundaries verified against the circuit):

1. `VK_SUBSTITUTION` — `proof_vk != registered_vk`
2. `PROOF_REUSED` — `proof_tx` already seen under a **different** `task_id`
   (same-task retry is not reuse; answered **without** a proof)
3. `THRESHOLD_MISMATCH` — `public_balance < minimum` (equality is valid)
4. `EXPIRED_CONDITION` — `current_block >= expiry_block` (expiry is strict)
5. `RECIPIENT_MISMATCH` — `recipient != condition_recipient`
6. `AMOUNT_OVERFLOW` — `amount > max_transfer` (equality is valid)
7. otherwise `APPROVE` / `VALID_CONDITION`

Response: `{decision, reason_code, proof_tx, proof, public_signals}` —
proof generated locally in ~0.4 s (13 public signals).

## Deploy

### Railway (recommended)

1. Push this folder to a **public GitHub repository**.
2. Railway → New Project → Deploy from GitHub repo → select the repo.
   (`railway.json` in this repo sets the start command: `node server.js`.)
3. Variables: set `AGENT_GAMES_HMAC_SECRET` (value from the dashboard's
   Rotate Secret — set it after registering the agent, then redeploy).
4. Settings → Networking → **Generate Domain** to get the public HTTPS URL,
   e.g. `https://<name>.up.railway.app`.
5. Your agent endpoint to register in the dashboard is the full URL:
   `https://<name>.up.railway.app/gatekeeper`
6. Check `https://<name>.up.railway.app/health` → `selfTest` must be `PASS`.

### Render (alternative)

`render.yaml` is included. Caveat: free web services **spin down when
idle** — a cold start can eat into the 60-second task deadline, so use an
always-on instance during scored rounds.

## Dashboard steps (owner, after deploy)

1. Register the agent endpoint (full `/gatekeeper` URL) in the dashboard.
2. **Rotate Secret** → put the value in the host's env as
   `AGENT_GAMES_HMAC_SECRET` → redeploy/restart.
3. Run the platform **preflight**, then at least one **practice task**
   (both are entry requirements). Agent should flip to **HEALTHY**.
4. Timing: entries lock while a round is open — do the steps above between
   rounds (rounds run 17:30–03:30 WIB).

## Troubleshooting

- Preflight: *"The endpoint must return signed protocol-v1 JSON"* →
  `AGENT_GAMES_HMAC_SECRET` is missing or wrong on the host.
- All requests 401 → secret mismatch, or try `AGENT_GAMES_HMAC_FORMAT=sha256=`.
- Practice proof rejected → try `GATEKEEPER_TASK_ID_MODE=numeric` or `hex`.
- `/health` selfTest FAIL → circuit artifacts missing/corrupt; re-download
  from `https://agentgames.zkverify.io/circuits/` (see STATUS.md checksums).

## Files

```
server.js                  HTTP server (HMAC, preflight, tasks, health)
lib/hmac.js                HMAC-SHA256 sign/verify (hex / sha256= formats)
lib/decide.js              7-case checklist + proof_tx seen-set
lib/prove.js               circuit input mapping + snarkjs proving/verify
lib/field.js               BN128 field + keccak-256 helpers (stdlib only)
circuits/                  official gatekeeper.wasm, gatekeeper_final.zkey,
                           verification_key.json (exported from the zkey)
test/harness.js            13 cases: all traps + boundaries vs the circuit
test/preflight-sim.js      platform simulation against the real server
scripts/export-vk.js       regenerate circuits/verification_key.json
railway.json, render.yaml  deploy configs
research/                  third-party reference material (see STATUS.md)
```

No wallet keys, no signing of transactions, no spending — the server only
judges tasks and proves its decisions. Secrets are read from the environment
and never logged.
