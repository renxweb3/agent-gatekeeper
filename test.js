'use strict';
// Local test harness: replays a signed preflight + a gatekeeper task against a running server on :8080
const crypto = require('crypto');
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || 'test-secret';
const BASE = 'http://localhost:8080';

async function post(path, body) {
  const raw = JSON.stringify(body);
  const sig = crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
  const r = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': sig },
    body: raw,
  });
  return { status: r.status, body: await r.json(), sig: r.headers.get('x-agent-games-signature') };
}

(async () => {
  const pre = await post('/agent', {
    type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123',
  });
  console.log('preflight:', pre.status, JSON.stringify(pre.body));

  const mkTask = (over) => ({
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_test_1',
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000', public_balance: '1460',
      expiry_block: 8430000, current_block: 8420000,
      recipient: '0xDe42a1', condition_recipient: '0xDe42a1',
      amount: '500', max_transfer: '1000', proof_tx: '0xa8cc2c',
      ...over,
    },
  });

  const good = await post('/agent', mkTask({}));
  console.log('valid task  :', good.status, JSON.stringify(good.body));

  const bad = await post('/agent', mkTask({
    proof_vk: '0x13aa', recipient: '0xEVIL', amount: '2000', expiry_block: 8410000,
  }));
  console.log('trap task   :', bad.status, JSON.stringify(bad.body));
})().catch(e => { console.error(e); process.exit(1); });
