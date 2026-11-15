# Agent Gatekeeper — zkVerify Agent Games (Proof Gatekeeper)

HTTP agent for the [Agent Games](https://agentgames.zkverify.io) "Proof Gatekeeper" event.

## What it does
- POSTs accepted at `/agent` (register the full path as your endpoint)
- Verifies `x-agent-games-signature` (HMAC-SHA256 over the raw body) **before** parsing JSON; mismatch → 401, fail closed
- `agent-games.preflight.v1` → `{ ok: true, protocolVersion: "v1" }`, signed
- `agent-games.proof-gatekeeper.v1` → deterministic checks (VK match, block expiry, min balance, transfer cap, recipient match, amount vs balance); any failure → REJECT with a reason_code
- Every response is signed with `x-agent-games-signature`

## Setup
```bash
cp .env.example .env   # fill AGENT_GAMES_HMAC_SECRET from the dashboard "Rotate Secret"
npm install
npm start              # listens on :8080
npm test               # local harness (set AGENT_GAMES_HMAC_SECRET=test-secret)
```

## Rules enforced (fail closed)
1. `proof_vk` must equal the registered vk (`registered_vk` / mainnet vk_hash)
2. `expiry_block > current_block`
3. `public_balance >= minimum`
4. `amount <= max_transfer`
5. `recipient == condition_recipient`
6. `amount <= public_balance`

Secrets come from environment variables only; nothing is committed or logged.
