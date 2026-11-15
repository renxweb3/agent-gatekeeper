'use strict';
/**
 * Proof Gatekeeper agent — zkVerify Agent Games
 * - Verifies HMAC over RAW body before parsing (fail closed)
 * - Preflight: { ok: true, protocolVersion: "v1" }
 * - Gatekeeper task: deterministic rule checks, REJECT by default
 * - All responses signed with x-agent-games-signature (HMAC-SHA256 hex of raw body)
 */
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const SECRET = (process.env.GATEKEEPER_HMAC_SECRET || process.env.AGENT_GAMES_HMAC_SECRET || '').trim();
const GATEKEEPER_VK_HASH = process.env.GATEKEEPER_VK_HASH ||
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

function hmacHex(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}

function verifySig(raw, header) {
  if (!SECRET) return false; // fail closed without secret
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

// Deterministic decision logic. Fail closed: REJECT unless every check passes.
function decide(input) {
  const checks = [
    ['VK_SUBSTITUTION',
      String(input.proof_vk).toLowerCase() === String(input.registered_vk).toLowerCase() ||
      String(input.proof_vk).toLowerCase() === GATEKEEPER_VK_HASH.toLowerCase()],
    ['PROOF_EXPIRED',
      Number(input.expiry_block) > Number(input.current_block)],
    ['INSUFFICIENT_PUBLIC_BALANCE',
      BigInt(input.public_balance) >= BigInt(input.minimum)],
    ['AMOUNT_EXCEEDS_LIMIT',
      BigInt(input.amount) <= BigInt(input.max_transfer)],
    ['RECIPIENT_MISMATCH',
      String(input.recipient).toLowerCase() === String(input.condition_recipient).toLowerCase()],
    ['AMOUNT_EXCEEDS_BALANCE',
      BigInt(input.amount) <= BigInt(input.public_balance)],
  ];
  for (const [code, ok] of checks) {
    if (!ok) return { decision: 'REJECT', reason_code: code };
  }
  return { decision: 'APPROVE', reason_code: 'ALL_CHECKS_PASSED' };
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, version: process.env.GIT_COMMIT_SHA || 'v4', source: process.env.GATEKEEPER_HMAC_SECRET ? 'GATEKEEPER_HMAC_SECRET' : (process.env.AGENT_GAMES_HMAC_SECRET ? 'AGENT_GAMES_HMAC_SECRET' : 'NONE'), secretSet: !!SECRET, secretFp: crypto.createHash('sha256').update(SECRET).digest('hex').slice(0, 16) }));
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
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
        const result = decide(body.input || {});
        result.task_id = body.task_id;
        result.proof_tx = (body.input || {}).proof_tx;
        return sendSigned(res, 200, result);
      }
      if (body.type === 'agent-games.steal-the-vfy.v1' || /steal|vfy|turn|match|strategy|commit/i.test(body.type || '')) {
        console.log('[STFV-IN]', raw);
        const inp = body.input || body;
        const turn = Number(inp.turn ?? inp.turn_number ?? inp.turnNumber ?? 0);
        const selfBal = BigInt(inp.self_balance ?? inp.selfBalance ?? inp.balance ?? 100);
        const oppBal = BigInt(inp.opponent_balance ?? inp.opponentBalance ?? 100);
        // Adaptive-ish deterministic strategy (private logic): pressure early, protect when rich.
        let action = 'HOLD';
        let amount = 0;
        if (oppBal > 0n && turn % 3 !== 2) {
          action = 'EXTRACT';
          amount = Number(oppBal > 20n ? 20n : oppBal);
        } else if (selfBal > 60n) {
          action = 'FORTIFY';
          amount = 10;
        }
        const h = require('js-sha3');
        const hash = h.keccak256(Buffer.concat([
          Buffer.from(String(inp.strategy_commitment ?? inp.strategyCommitment ?? '0'), 'utf8'),
          Buffer.from(String(inp.match_id ?? inp.matchId ?? '0'), 'utf8'),
          Buffer.from(String(turn), 'utf8'),
          Buffer.from(String(selfBal), 'utf8'),
          Buffer.from(String(oppBal), 'utf8'),
          Buffer.from(String(action), 'utf8'),
        ]));
        const resp = { action, amount, publicInputsHash: '0x' + hash, task_id: body.task_id };
        console.log('[STFV-OUT]', JSON.stringify(resp));
        return sendSigned(res, 200, resp);
      }
      console.log('[UNKNOWN-TASK]', body.type || '(no type)', raw.slice(0, 2000));
      return sendSigned(res, 200, { ok: false, error: 'unknown_task_type', received_type: body.type });
    } catch (e) {
      return sendSigned(res, 200, { decision: 'REJECT', reason_code: 'PROCESSING_ERROR', error: e.message });
    }
  });
});

server.listen(PORT, () => console.log(`gatekeeper agent listening on :${PORT}`));
