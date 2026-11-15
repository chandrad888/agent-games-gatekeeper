// Preflight simulation: boots the real server on a local port with a DUMMY
// HMAC secret and plays the platform's role:
//   1. GET /health                       -> ok, hmacConfigured, selfTest PASS
//   2. POST preflight, UNSIGNED          -> 401
//   3. POST preflight, wrong signature   -> 401
//   4. POST preflight, correctly signed  -> 200 {ok, protocolVersion:"v1"}
//                                           + response signature verifies
//   5. POST valid task, signed           -> APPROVE/VALID_CONDITION + proof
//                                           that verifies locally; response
//                                           signature verifies
//   6. POST trap task, signed            -> REJECT/THRESHOLD_MISMATCH + proof
//   7. POST reused proof_tx (new task)   -> REJECT/PROOF_REUSED, no proof
// Run: node test/preflight-sim.js
const { spawn } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const { verifyLocally } = require('../lib/prove');
const { verifySignature } = require('../lib/hmac');

const PORT = 18099;
const SECRET = 'dummy-secret-for-local-preflight-sim';
const BASE = `http://127.0.0.1:${PORT}`;
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

function sign(body) {
  return crypto.createHmac('sha256', SECRET).update(body).digest('hex');
}

async function post(pathname, body, headers = {}) {
  const res = await fetch(BASE + pathname, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body });
  const text = await res.text();
  return { status: res.status, text, sig: res.headers.get('x-agent-games-signature') };
}

function envelope(input, taskId) {
  return JSON.stringify({
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId,
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input,
  });
}

function taskInput(overrides = {}) {
  return Object.assign({
    registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
    expiry_block: '8430000', current_block: '8420000',
    recipient: '0x1111111111111111111111111111111111111111',
    condition_recipient: '0x1111111111111111111111111111111111111111',
    amount: '500', max_transfer: '1000', proof_tx: '0xsimproof1',
  }, overrides);
}

async function waitHealth(timeoutMs = 30000) {
  const t0 = Date.now();
  for (;;) {
    try {
      const r = await fetch(BASE + '/health');
      if (r.ok) {
        const j = await r.json();
        if (j.gatekeeper && j.gatekeeper.selfTest !== 'pending') return j;
      }
    } catch { /* not up yet */ }
    if (Date.now() - t0 > timeoutMs) throw new Error('server did not become ready');
    await new Promise((r) => setTimeout(r, 300));
  }
}

(async () => {
  const results = [];
  const check = (name, ok, extra = '') => {
    results.push(ok);
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  — ' + extra : ''}`);
  };

  const child = spawn('node', [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, SEEN_STORE_PATH: '/tmp/agentgames-sim-seen.json' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stderr.on('data', (d) => process.stderr.write('[server] ' + d));
  try {
    const health = await waitHealth();
    check('GET /health: ok + hmacConfigured + selfTest PASS',
      health.ok === true && health.gatekeeper.hmacConfigured === true && String(health.gatekeeper.selfTest).startsWith('PASS'),
      JSON.stringify(health.gatekeeper));

    const pre = JSON.stringify({ type: 'agent-games.preflight.v1' });
    const unsigned = await post('/gatekeeper', pre);
    check('preflight unsigned -> 401', unsigned.status === 401);
    const wrongSig = await post('/gatekeeper', pre, { 'x-agent-games-signature': 'deadbeef' });
    check('preflight wrong signature -> 401', wrongSig.status === 401);
    const signed = await post('/gatekeeper', pre, { 'x-agent-games-signature': sign(pre) });
    let preOk = false;
    try { const j = JSON.parse(signed.text); preOk = j.ok === true && j.protocolVersion === 'v1'; } catch {}
    check('preflight signed -> 200 {ok:true, protocolVersion:"v1"}', signed.status === 200 && preOk);
    check('preflight response signature verifies', verifySignature(SECRET, signed.text, signed.sig, 'hex'));

    const validBody = envelope(taskInput(), 'gk_sim_1');
    const t0 = Date.now();
    const valid = await post('/gatekeeper', validBody, { 'x-agent-games-signature': sign(validBody) });
    const validMs = Date.now() - t0;
    let v = {};
    try { v = JSON.parse(valid.text); } catch {}
    check('valid task -> APPROVE/VALID_CONDITION', valid.status === 200 && v.decision === 'APPROVE' && v.reason_code === 'VALID_CONDITION', `${validMs}ms`);
    check('valid task response signature verifies', verifySignature(SECRET, valid.text, valid.sig, 'hex'));
    let proofOk = false;
    if (v.proof && v.public_signals) proofOk = await verifyLocally(v.public_signals, v.proof);
    check('valid task proof verifies locally (13 public signals)', proofOk && v.public_signals.length === 13);

    const trapBody = envelope(taskInput({ public_balance: '100', proof_tx: '0xsimproof2' }), 'gk_sim_2');
    const trap = await post('/gatekeeper', trapBody, { 'x-agent-games-signature': sign(trapBody) });
    let tr = {};
    try { tr = JSON.parse(trap.text); } catch {}
    check('trap task -> REJECT/THRESHOLD_MISMATCH', trap.status === 200 && tr.decision === 'REJECT' && tr.reason_code === 'THRESHOLD_MISMATCH');
    let trapProofOk = false;
    if (tr.proof && tr.public_signals) trapProofOk = await verifyLocally(tr.public_signals, tr.proof);
    check('trap task proof verifies locally', trapProofOk);

    const reuseBody = envelope(taskInput({ proof_tx: '0xsimproof1' }), 'gk_sim_3');
    const reuse = await post('/gatekeeper', reuseBody, { 'x-agent-games-signature': sign(reuseBody) });
    let ru = {};
    try { ru = JSON.parse(reuse.text); } catch {}
    check('reused proof_tx under new task_id -> REJECT/PROOF_REUSED without proof',
      reuse.status === 200 && ru.decision === 'REJECT' && ru.reason_code === 'PROOF_REUSED' && !ru.proof);
  } finally {
    child.kill('SIGTERM');
  }

  const passed = results.filter(Boolean).length;
  console.log(`\n${passed}/${results.length} preflight-sim checks passed`);
  process.exit(passed === results.length ? 0 : 1);
})().catch((e) => { console.error('SIM ERROR:', e); process.exit(1); });
