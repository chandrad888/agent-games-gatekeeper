// Gatekeeper harness: every documented trap type + boundary cases, checked
// against the circuit itself. A case passes only if (a) decide() returns the
// expected decision/reason_code AND (b) a Groth16 proof for that decision
// verifies locally (PROOF_REUSED is checked decision-only — it has no proof).
// Run: node test/harness.js
const { createDecider } = require('../lib/decide');
const { proveTask, verifyLocally } = require('../lib/prove');

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const OTHER_VK = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const ADDR = '0x1111111111111111111111111111111111111111';
const OTHER_ADDR = '0x2222222222222222222222222222222222222222';
const MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';

function base(overrides = {}) {
  return Object.assign({
    task_id: 'gk_test_1', registered_vk: VK, proof_vk: VK,
    minimum: '1000', public_balance: '1460', expiry_block: '8430000', current_block: '8420000',
    recipient: ADDR, condition_recipient: ADDR,
    amount: '500', max_transfer: '1000', proof_tx: '0xtestproof1',
  }, overrides);
}

const CASES = [
  ['VALID_CONDITION', base(), 'APPROVE', 'VALID_CONDITION'],
  ['VK_SUBSTITUTION', base({ proof_vk: OTHER_VK, proof_tx: '0xtestproof2' }), 'REJECT', 'VK_SUBSTITUTION'],
  ['THRESHOLD_MISMATCH (999 < 1000)', base({ public_balance: '999', proof_tx: '0xtestproof3' }), 'REJECT', 'THRESHOLD_MISMATCH'],
  ['EXPIRED_CONDITION (8430001 > 8430000)', base({ current_block: '8430001', proof_tx: '0xtestproof4' }), 'REJECT', 'EXPIRED_CONDITION'],
  ['RECIPIENT_MISMATCH', base({ recipient: OTHER_ADDR, proof_tx: '0xtestproof5' }), 'REJECT', 'RECIPIENT_MISMATCH'],
  ['AMOUNT_OVERFLOW (1500 > 1000)', base({ amount: '1500', proof_tx: '0xtestproof6' }), 'REJECT', 'AMOUNT_OVERFLOW'],
  ['boundary: balance == minimum (1000)', base({ public_balance: '1000', proof_tx: '0xtestproof7' }), 'APPROVE', 'VALID_CONDITION'],
  ['boundary: current == expiry (8430000) -> EXPIRED (strict)', base({ current_block: '8430000', proof_tx: '0xtestproof8' }), 'REJECT', 'EXPIRED_CONDITION'],
  ['boundary: current == expiry - 1 (8429999)', base({ current_block: '8429999', proof_tx: '0xtestproof8b' }), 'APPROVE', 'VALID_CONDITION'],
  ['boundary: amount == max (1000)', base({ amount: '1000', proof_tx: '0xtestproof9' }), 'APPROVE', 'VALID_CONDITION'],
];

(async () => {
  const decider = createDecider(null);
  let pass = 0;
  for (const [name, task, wantDecision, wantReason] of CASES) {
    const t0 = Date.now();
    const got = decider.decide(task);
    const decisionOk = got.decision === wantDecision && got.reason_code === wantReason;
    let proofOk = false;
    let proofMs = 0;
    try {
      const { proof, publicSignals } = await proveTask(task, got.decision, MODE);
      proofMs = Date.now() - t0;
      proofOk = await verifyLocally(publicSignals, proof);
    } catch { proofOk = false; }
    const ok = decisionOk && proofOk;
    if (ok) pass++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  -> ${got.decision}/${got.reason_code} (want ${wantDecision}/${wantReason})  proof=${proofOk ? 'verify OK' : 'FAIL'}  ${proofMs}ms`);
  }

  const reuse = decider.decide(base({ task_id: 'gk_test_99', proof_tx: '0xtestproof1' }));
  const reuseOk = reuse.decision === 'REJECT' && reuse.reason_code === 'PROOF_REUSED';
  if (reuseOk) pass++;
  console.log(`${reuseOk ? 'PASS' : 'FAIL'}  PROOF_REUSED (same proof_tx, other task_id)  -> ${reuse.decision}/${reuse.reason_code}`);

  const retry = decider.decide(base({ task_id: 'gk_test_1', proof_tx: '0xtestproof1' }));
  const retryOk = retry.decision === 'APPROVE';
  if (retryOk) pass++;
  console.log(`${retryOk ? 'PASS' : 'FAIL'}  same task_id retry is not reuse  -> ${retry.decision}/${retry.reason_code}`);

  // Negative control: the circuit must REFUSE a wrong decision (no witness).
  let negativeOk = false;
  try {
    await proveTask(base({ proof_tx: '0xneg' }), 'REJECT', MODE);
  } catch { negativeOk = true; }
  if (negativeOk) pass++;
  console.log(`${negativeOk ? 'PASS' : 'FAIL'}  negative control: REJECT of a valid task is unprovable`);

  const total = CASES.length + 3;
  console.log(`\n${pass}/${total} gatekeeper cases passed`);
  process.exit(pass === total ? 0 : 1);
})().catch((e) => { console.error('HARNESS ERROR:', e); process.exit(1); });
