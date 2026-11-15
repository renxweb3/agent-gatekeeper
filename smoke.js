const { spawn } = require('child_process');
const S = '8c9dbece48dc50943418a67d2d3c98d9d5f5fd576d2bd46d26801e37b2be3428';
const proc = spawn('node', ['server.js'], {
  env: {
    ...process.env, PORT: '8098', GATEKEEPER_HMAC_SECRET: S,
    STRATEGY_PARAMS: '[10,0,0,0,0,0,0,0]',
    STRATEGY_SALT: '0x24f248abc3719f8ca3875c293fdadc7acf0ae877f65453d7d572ab74298499',
    STRATEGY_COMMITMENT: '0x234026b486e03ce8ecaeb74dd123588cf5ee8cf6021d788fbfc9ffd58d4ea9bb',
  },
});
setTimeout(async () => {
  const crypto = require('crypto');
  const env = {
    protocolVersion: 'v1', eventId: 'steal-the-vfy', mode: 'practice',
    matchId: '530ed743-c75e-4946-b814-154de7b487cd', turn: 1,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 60000).toISOString(),
    state: { selfBalance: '100', opponentBalance: '100', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null, priorTurnHash: '0x0' },
    resolverVersion: 'v1', nonce: 'x',
  };
  const raw = JSON.stringify(env);
  const sig = crypto.createHmac('sha256', S).update(raw).digest('hex');
  const r = await fetch('http://localhost:8098/agent', { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent-games-signature': sig }, body: raw });
  const body = await r.json();
  console.log('action:', JSON.stringify(body.action));
  console.log('keys:', Object.keys(body.policyProof || {}).join(','));
  console.log('proof?', body.policyProof && body.policyProof.proof ? 'YES' : 'NO');
  proc.kill();
  process.exit(0);
}, 8000);
