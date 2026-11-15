// Proof Gatekeeper agent — zkVerify Agent Games, Season 01.
//
//   POST /gatekeeper   task envelopes + preflight (also accepts POST /)
//   GET  /health       readiness: HMAC configured? startup self-test result?
//   GET  /             service info
//
// Protocol (see STATUS.md for sources):
//   - Every inbound POST is HMAC-SHA256 verified over the RAW body against
//     the `x-agent-games-signature` header BEFORE parsing (when the secret
//     is configured). Bad signature -> 401.
//   - Preflight {"type":"agent-games.preflight.v1"} is answered
//     {ok:true, protocolVersion:"v1"}, signed.
//   - Task responses are {decision, reason_code, proof_tx, proof,
//     public_signals}, signed the same way. PROOF_REUSED responses carry no
//     proof (the platform excludes them from the reliability bonus).
//   - Fail closed: on any uncertainty the answer is a REJECT, never a guess.
//   - No wallet, no keys, no spending: this server only judges and proves.
const fs = require('fs');
const path = require('path');
const http = require('http');

(function loadEnv() {
  try {
    for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) {
      const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* no .env file — real environment only */ }
})();

const { verifySignature, signatureFor } = require('./lib/hmac');
const { createDecider } = require('./lib/decide');
const { proveTask, verifyLocally } = require('./lib/prove');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex'; // or 'sha256='
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak'; // or 'numeric' / 'hex'
const SEEN_STORE_PATH = process.env.SEEN_STORE_PATH || path.join(__dirname, 'data', 'seen.json');
const MAX_BODY = 1024 * 1024;

const decider = createDecider(SEEN_STORE_PATH);
let selfTest = 'pending';

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) {
    headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body, HMAC_FORMAT);
  }
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function verifyInbound(rawBody, req) {
  if (!HMAC_SECRET) return true; // local/dev mode; health reports it
  return verifySignature(HMAC_SECRET, rawBody, req.headers['x-agent-games-signature'], HMAC_FORMAT);
}

const REQUIRED_FIELDS = [
  'registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block',
  'current_block', 'recipient', 'condition_recipient', 'amount',
  'max_transfer', 'proof_tx',
];

async function handleGatekeeper(obj) {
  // Envelope: {type, task_id, mode, issued_at, deadline_at, input:{...}}.
  // Accept fields at the top level too, and task_id from either level.
  const input = obj.input && typeof obj.input === 'object' ? obj.input : obj;
  const task = { ...input, task_id: input.task_id ?? obj.task_id ?? '' };

  for (const f of REQUIRED_FIELDS) {
    if (task[f] === undefined || task[f] === null || task[f] === '') {
      log('[gatekeeper] malformed task (missing ' + f + ') task_id=' + task.task_id);
      return { decision: 'REJECT', reason_code: 'INVALID_TASK', proof_tx: String(task.proof_tx || '') };
    }
  }

  const t0 = Date.now();
  const { decision, reason_code } = decider.decide(task);
  const proofTx = String(task.proof_tx || '');

  if (reason_code === 'PROOF_REUSED') {
    log(`[gatekeeper] task=${task.task_id} ${decision}/${reason_code} (no proof) ${Date.now() - t0}ms`);
    return { decision, reason_code, proof_tx: proofTx };
  }

  try {
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    log(`[gatekeeper] task=${task.task_id} ${decision}/${reason_code} proof ok ${Date.now() - t0}ms`);
    return { decision, reason_code, proof_tx: proofTx, proof, public_signals: publicSignals };
  } catch (e) {
    // The circuit refused the witness (should not happen when decide() is
    // correct) or proving failed: still return the decision, without proof.
    log(`[gatekeeper] task=${task.task_id} ${decision}/${reason_code} PROOF FAILED: ${e.message}`);
    return { decision, reason_code, proof_tx: proofTx };
  }
}

// Startup self-test: prove the official sample scenario on a throwaway
// decider and verify the proof locally, so /health can report PASS.
async function runSelfTest() {
  try {
    const testDecider = createDecider(null);
    const task = {
      task_id: 'gk_selftest_1',
      registered_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      proof_vk: '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0',
      minimum: '1000', public_balance: '1460',
      expiry_block: '8430000', current_block: '8420000',
      recipient: '0x1111111111111111111111111111111111111111',
      condition_recipient: '0x1111111111111111111111111111111111111111',
      amount: '500', max_transfer: '1000', proof_tx: '0xselftest',
    };
    const { decision } = testDecider.decide(task);
    const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
    const ok = await verifyLocally(publicSignals, proof);
    selfTest = ok && decision === 'APPROVE'
      ? 'PASS (APPROVE proof generated and verified locally)'
      : 'FAIL (unexpected self-test result)';
  } catch (e) {
    selfTest = 'FAIL: ' + e.message;
  }
  log('[server] gatekeeper self-test:', selfTest);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, {
        ok: true,
        service: 'agent-games-gatekeeper',
        gatekeeper: {
          hmacConfigured: !!HMAC_SECRET,
          hmacFormat: HMAC_FORMAT,
          taskIdMode: TASK_ID_MODE,
          selfTest,
          seenProofCount: decider.seen.size,
        },
        uptimeSec: Math.floor(process.uptime()),
      });
    }
    if (req.method === 'GET' && url.pathname === '/') {
      return sendJson(res, 200, {
        service: 'agent-games-gatekeeper',
        track: 'proof-gatekeeper',
        endpoints: ['POST /gatekeeper', 'GET /health'],
      });
    }
    if (req.method !== 'POST' || (url.pathname !== '/gatekeeper' && url.pathname !== '/')) {
      return sendJson(res, 404, { error: 'not found' });
    }

    const rawBody = await readBody(req);
    if (!verifyInbound(rawBody, req)) {
      log('[warn] HMAC mismatch on', url.pathname);
      return sendJson(res, 401, { error: 'bad signature' });
    }

    let obj;
    try {
      obj = JSON.parse(rawBody.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid JSON' });
    }

    if (obj && obj.type === 'agent-games.preflight.v1') {
      return sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, true);
    }

    const body = await handleGatekeeper(obj);
    return sendJson(res, 200, body, true);
  } catch (e) {
    log('[server] unhandled error:', e && e.message);
    return sendJson(res, 500, { error: 'internal error' });
  }
});

server.listen(PORT, HOST, async () => {
  log(`[server] listening on ${HOST}:${PORT} (POST /gatekeeper, GET /health)`);
  log(`[server] HMAC secret: ${HMAC_SECRET ? 'configured' : 'NOT SET — inbound verification disabled; set AGENT_GAMES_HMAC_SECRET before going live'}`);
  log(`[server] taskId mode: ${TASK_ID_MODE}; hmac format: ${HMAC_FORMAT}`);
  await runSelfTest();
});
