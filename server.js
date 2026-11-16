'use strict';
/**
 * Agent Games agent — Proof Gatekeeper + Steal the VFY
 * - HMAC verify over RAW body before parsing (fail closed)
 * - Preflight: { ok: true, protocolVersion: "v1" }
 * - Gatekeeper task: deterministic rule checks, REJECT by default
 * - Steal the VFY turn: circuit-driven strategy + Groth16 policy proof
 * - All responses signed with x-agent-games-signature (HMAC-SHA256 hex of raw body)
 */
const http = require('http');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 8080;
const SECRET = (process.env.GATEKEEPER_HMAC_SECRET || process.env.AGENT_GAMES_HMAC_SECRET || '').trim();
const GATEKEEPER_VK_HASH = process.env.GATEKEEPER_VK_HASH ||
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

const STRATEGY_PARAMS = JSON.parse(process.env.STRATEGY_PARAMS || '[10,0,0,0,0,0,0,0]');
const STRATEGY_SALT = (process.env.STRATEGY_SALT || '').trim();
const STRATEGY_COMMITMENT = (process.env.STRATEGY_COMMITMENT || '').trim();
const CIRCUIT_DIR = path.join(__dirname, 'circuits');
const VFY_WASM = path.join(CIRCUIT_DIR, 'vfy-policy.wasm');
const VFY_ZKEY = path.join(CIRCUIT_DIR, 'vfy-policy_final.zkey');

const ACTION_CODE = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

function hmacHex(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}

function verifySig(raw, header) {
  if (!SECRET) return false;
  if (!header) return false;
  const h = header.trim().toLowerCase();
  const hex = h.startsWith('sha256=') ? h.slice(7) : h;
  const expected = hmacHex(raw);
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(hex, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sendSigned(res, status, obj) {
  const raw = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': hmacHex(raw),
  });
  res.end(raw);
}

// ---------- Proof Gatekeeper ----------
function decideGatekeeper(input) {
  const checks = [
    ['VK_SUBSTITUTION',
      String(input.proof_vk).toLowerCase() === String(input.registered_vk).toLowerCase() ||
      String(input.proof_vk).toLowerCase() === GATEKEEPER_VK_HASH.toLowerCase()],
    ['PROOF_EXPIRED', Number(input.expiry_block) > Number(input.current_block)],
    ['INSUFFICIENT_PUBLIC_BALANCE', BigInt(input.public_balance) >= BigInt(input.minimum)],
    ['AMOUNT_EXCEEDS_LIMIT', BigInt(input.amount) <= BigInt(input.max_transfer)],
    ['RECIPIENT_MISMATCH',
      String(input.recipient).toLowerCase() === String(input.condition_recipient).toLowerCase()],
    ['AMOUNT_EXCEEDS_BALANCE', BigInt(input.amount) <= BigInt(input.public_balance)],
  ];
  for (const [code, ok] of checks) {
    if (!ok) return { decision: 'REJECT', reason_code: code };
  }
  return { decision: 'APPROVE', reason_code: 'ALL_CHECKS_PASSED' };
}

// ---------- Steal the VFY ----------
// ---- Gatekeeper ZK proof (Groth16, BN254 field) --------------------------
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
async function proveGatekeeper(task, decision) {
  const i = task.input || {};
  const fieldOf = (s) => (BigInt(s) % FIELD).toString();
  const uintOf = (v) => BigInt(v).toString();
  const taskIdField = (BigInt('0x' + crypto.createHash('sha256').update(String(task.task_id || '')).digest('hex')) % FIELD).toString();
  const salt = (BigInt('0x' + crypto.createHmac('sha256', SECRET).update('gatekeeper-proof-salt-v1:' + task.mode + ':' + task.task_id).digest('hex')) % FIELD).toString();
  const wit = {
    registeredVkHash: fieldOf(i.registered_vk), proofVkHash: fieldOf(i.proof_vk),
    minimum: uintOf(i.minimum), publicBalance: uintOf(i.public_balance),
    expiryBlock: uintOf(i.expiry_block), currentBlock: uintOf(i.current_block),
    recipient: fieldOf(i.recipient), conditionRecipient: fieldOf(i.condition_recipient),
    amount: uintOf(i.amount), maxTransfer: uintOf(i.max_transfer),
    decision: decision.decision === 'APPROVE' ? '1' : '0', taskId: taskIdField, salt,
  };
  const snarkjs = require('snarkjs');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    wit, path.join(__dirname, 'gatekeeper.wasm'), path.join(__dirname, 'gatekeeper_final.zkey'));
  return { proof, publicSignals };
}

// ---- Kurier on-chain submission (zkVerify) ------------------------------
const KURIER_API_KEY = (process.env.KURIER_API_KEY || '').trim();
const KURIER_URL = 'https://api.kurier.xyz/api/v1';
const VFY_VK_HASH = '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
const kurierStats = { submitted: 0, finalized: 0, failed: 0, lastTx: null };

async function kurierSubmit(proof, publicSignals, vkHash) {
  if (!KURIER_API_KEY) return null;
  const body = JSON.stringify({ proofType: 'groth16', vkRegistered: true,
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    proofData: { vk: vkHash, proof, publicSignals } });
  const r = await fetch(`${KURIER_URL}/submit-proof/${KURIER_API_KEY}`,
    { method: 'POST', headers: { 'content-type': 'application/json' }, body });
  const j = await r.json();
  if (!j.jobId) throw new Error('kurier_no_jobid: ' + JSON.stringify(j).slice(0, 200));
  kurierStats.submitted++;
  return j.jobId;
}

async function kurierWaitTx(jobId, timeoutMs = 25000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    await new Promise(r => setTimeout(r, 4000));
    const r = await fetch(`${KURIER_URL}/job-status/${KURIER_API_KEY}/${jobId}`);
    const j = await r.json();
    if (j.txHash) { kurierStats.finalized++; kurierStats.lastTx = j.txHash; return j.txHash; }
    if (j.status === 'Failed') { kurierStats.failed++; return null; }
  }
  return null;
}

// Fire-and-forget: submit + wait, record tx, never blocks the response.
function kurierBackground(proof, publicSignals, vkHash, tag) {
  if (!KURIER_API_KEY) return;
  kurierSubmit(proof, publicSignals, vkHash)
    .then(jobId => kurierWaitTx(jobId).then(tx => console.log(`[KURIER] ${tag} job=${jobId} tx=${tx || 'pending'}`)))
    .catch(e => { kurierStats.failed++; console.log('[KURIER-FAIL]', tag, String(e.message || e).slice(0, 200)); });
}

// Circuit-enforced decision list (must match vfy-policy exactly):
//   1. FORTIFY when selfBalance < params[1]
//   2. else HOLD when opponentBalance <= params[2] OR params[3] == 1
//   3. else EXTRACT with amount == params[0]
function decideVfy(selfBalance, opponentBalance) {
  const p = STRATEGY_PARAMS;
  if (BigInt(selfBalance) < BigInt(p[1])) return { type: 'FORTIFY' };
  if (BigInt(opponentBalance) <= BigInt(p[2]) || BigInt(p[3]) === 1n) return { type: 'HOLD' };
  return { type: 'EXTRACT', amount: Number(p[0]) };
}

// keccak256 of ABI-packed 32-byte BE fields (official Build page spec)
function publicInputsHash(commitmentHash, matchId, turn, selfBalance, opponentBalance, action, amount) {
  const { keccak256 } = require('js-sha3');
  const to32 = (v) => {
    let hex = BigInt(v).toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
  };
  const matchBig = BigInt('0x' + matchId.replace(/-/g, ''));
  const buf = Buffer.concat([
    to32(BigInt(commitmentHash)),
    to32(matchBig),
    to32(BigInt(turn)),
    to32(BigInt(selfBalance)),
    to32(BigInt(opponentBalance)),
    to32(ACTION_CODE[action.type]),
    to32(BigInt(amount)),
    to32(1n), // circuitVersion v1
  ]);
  return '0x' + keccak256(buf);
}

let proofChain = Promise.resolve(); // serialize snarkjs runs
const idemCache = new Map();

function makeVfyProof(envelope, action, amount) {
  const p = proofChain.then(async () => {
    const snarkjs = require('snarkjs');
    const commitment = (envelope.strategyCommitment && envelope.strategyCommitment.hash)
      ? BigInt(envelope.strategyCommitment.hash).toString()
      : BigInt(STRATEGY_COMMITMENT).toString();
    const inputs = {
      commitment,
      matchId: BigInt('0x' + envelope.matchId.replace(/-/g, '')).toString(),
      selfBalance: BigInt(envelope.state.selfBalance).toString(),
      opponentBalance: BigInt(envelope.state.opponentBalance).toString(),
      action: ACTION_CODE[action.type].toString(),
      amount: String(amount || 0),
      circuitVersion: '1',
      turnNumber: BigInt(envelope.turn).toString(),
      salt: BigInt(STRATEGY_SALT).toString(),
      strategyParams: STRATEGY_PARAMS.map(String),
    };
    const started = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, VFY_WASM, VFY_ZKEY);
    console.log(`[VFY-PROOF] turn=${envelope.turn} action=${action.type} amount=${amount} ms=${Date.now() - started}`);
    kurierBackground(proof, publicSignals, VFY_VK_HASH, `vfy:${envelope.matchId}:t${envelope.turn}`);
    return { proof, publicSignals };
  });
  proofChain = p.catch(() => {});
  return p;
}

async function handleVfyTurn(res, envelope, idemKeyRaw) {
  // idempotencyKey must be a UUID: derive a deterministic UUID from match+turn when the platform omits it
  const deriveUuid = () => {
    const h = crypto.createHash('sha256').update(`${envelope.matchId}:${envelope.turn}`).digest('hex');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
  };
  const cacheKey = (idemKeyRaw && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(idemKeyRaw))
    ? idemKeyRaw : deriveUuid();
  if (idemCache.has(cacheKey)) {
    return sendSigned(res, 200, idemCache.get(cacheKey));
  }
  const state = envelope.state || {};
  const action = decideVfy(state.selfBalance ?? 100, state.opponentBalance ?? 100);
  const amount = action.type === 'EXTRACT' ? action.amount : 0;
  const hash = publicInputsHash(
    (envelope.strategyCommitment && envelope.strategyCommitment.hash) || STRATEGY_COMMITMENT,
    envelope.matchId, envelope.turn, state.selfBalance ?? 100, state.opponentBalance ?? 100,
    action, amount);
  let policyProof = { circuitVersion: 'v1', publicInputsHash: hash };
  try {
    if (STRATEGY_SALT && STRATEGY_COMMITMENT) {
      const { proof, publicSignals } = await makeVfyProof(envelope, action, amount);
      policyProof.proof = proof;
      policyProof.publicSignals = publicSignals;
    } else {
      console.log('[VFY] salt/commitment missing — no proof (fail closed)');
    }
  } catch (e) {
    console.log('[VFY-PROOF-FAIL]', String(e.message || e).slice(0, 300));
  }
  const response = {
    protocolVersion: 'v1',
    matchId: envelope.matchId,
    turn: envelope.turn,
    action,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: cacheKey,
  };
  if (idemCache.size > 500) idemCache.clear();
  idemCache.set(cacheKey, response);
  return sendSigned(res, 200, response);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, version: 'v6', secretSet: !!SECRET,
      strategy: STRATEGY_COMMITMENT ? STRATEGY_COMMITMENT.slice(0, 10) + '…' : 'unset',
      kurier: kurierStats }));
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks).toString('utf8');
    try {
      if (!verifySig(raw, req.headers['x-agent-games-signature'])) {
        return sendSigned(res, 401, { ok: false, error: 'invalid_signature' });
      }
      const body = JSON.parse(raw);
      if (body.type === 'agent-games.preflight.v1') {
        return sendSigned(res, 200, { ok: true, protocolVersion: 'v1' });
      }
      if (body.type === 'agent-games.proof-gatekeeper.v1') {
        const result = decideGatekeeper(body.input || {});
        result.task_id = body.task_id;
        result.proof_tx = (body.input || {}).proof_tx;
        try {
          const { proof, publicSignals } = await proveGatekeeper(body, result);
          result.proof = proof;
          result.public_signals = publicSignals;
          kurierBackground(proof, publicSignals, GATEKEEPER_VK_HASH, 'gk:' + body.task_id);
        } catch (e) {
          console.log('[GK-PROOF-FAIL]', String(e.message || e).slice(0, 200));
          result.proof_error = 'proof_generation_failed';
        }
        return sendSigned(res, 200, result);
      }
      if (body.eventId === 'steal-the-vfy') {
        return handleVfyTurn(res, body, body.idempotencyKey);
      }
      console.log('[UNKNOWN-TASK]', body.type || body.eventId || '(none)', raw.slice(0, 1500));
      return sendSigned(res, 200, { ok: false, error: 'unknown_task_type', received_type: body.type });
    } catch (e) {
      console.log('[ERROR]', String(e.message || e).slice(0, 300));
      return sendSigned(res, 200, { decision: 'REJECT', reason_code: 'PROCESSING_ERROR', error: e.message });
    }
  });
});

server.listen(PORT, () => console.log(`agent listening on :${PORT} (params=${STRATEGY_PARAMS.join(',')})`));
