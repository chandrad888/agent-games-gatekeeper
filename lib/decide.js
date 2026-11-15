// Proof Gatekeeper — deterministic decision logic for the 7 documented cases.
// The circuit is the referee: it enforces decision == APPROVE if and only if
// every circuit check passes (a wrong decision fails witness generation), so
// this checklist must match the circuit exactly. Check order below is the
// order used by a live platform-verified participant agent (first failing
// check determines reason_code); each competition task carries a single trap,
// so ordering only matters for multi-fault edge cases.
//
//   VK_SUBSTITUTION    proof_vk != registered_vk                (REJECT)
//   PROOF_REUSED       proof_tx already seen under a DIFFERENT  (REJECT, no proof)
//                      task_id — a retry of the SAME task_id is not reuse
//   THRESHOLD_MISMATCH public_balance < minimum                 (REJECT)
//   EXPIRED_CONDITION  current_block >= expiry_block            (REJECT)
//   RECIPIENT_MISMATCH recipient != condition_recipient         (REJECT)
//   AMOUNT_OVERFLOW    amount > max_transfer                    (REJECT)
//   else VALID_CONDITION                                        (APPROVE)
//
// Boundaries (verified against the circuit — see test/harness.js):
//   - public_balance == minimum is VALID (threshold inclusive).
//   - amount == max_transfer is VALID (cap inclusive).
//   - expiry is STRICT: valid only while current_block < expiry_block;
//     current_block == expiry_block is already EXPIRED.
const fs = require('fs');
const path = require('path');

// A decider owns a proof_tx seen-set: Map<proof_tx(lowercased), task_id>.
// `storePath` (optional) persists the set as JSON so reuse detection survives
// restarts on hosts with a writable filesystem; persistence is best-effort
// and never breaks a decision.
function createDecider(storePath) {
  const seen = new Map();

  if (storePath) {
    try {
      const raw = fs.readFileSync(storePath, 'utf8');
      for (const [k, v] of JSON.parse(raw)) seen.set(k, v);
    } catch { /* no store yet — start empty */ }
  }

  function persist() {
    if (!storePath) return;
    try {
      fs.mkdirSync(path.dirname(storePath), { recursive: true });
      const tmp = storePath + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify([...seen.entries()]));
      fs.renameSync(tmp, storePath);
    } catch { /* best effort only */ }
  }

  function decide(input) {
    const registeredVk = String(input.registered_vk || '').toLowerCase();
    const proofVk = String(input.proof_vk || '').toLowerCase();
    const minimum = BigInt(input.minimum);
    const publicBalance = BigInt(input.public_balance);
    const expiryBlock = BigInt(input.expiry_block);
    const currentBlock = BigInt(input.current_block);
    const recipient = String(input.recipient || '').toLowerCase();
    const conditionRecipient = String(input.condition_recipient || '').toLowerCase();
    const amount = BigInt(input.amount);
    const maxTransfer = BigInt(input.max_transfer);
    const proofTx = String(input.proof_tx || '').toLowerCase();
    const taskId = String(input.task_id || '');

    if (proofVk !== registeredVk) {
      return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
    }

    if (proofTx) {
      const prevTask = seen.get(proofTx);
      if (prevTask !== undefined && prevTask !== taskId) {
        return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
      }
      if (prevTask === undefined) {
        seen.set(proofTx, taskId);
        persist();
      }
    }

    if (publicBalance < minimum) {
      return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
    }
    if (currentBlock >= expiryBlock) {
      return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
    }
    if (recipient !== conditionRecipient) {
      return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
    }
    if (amount > maxTransfer) {
      return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
    }

    return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
  }

  return { decide, seen };
}

module.exports = { createDecider };
