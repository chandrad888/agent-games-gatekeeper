// Proof Gatekeeper — Groth16 proof generation with snarkjs 0.7.6 and the
// official circuit artifacts in ../circuits/.
//
// Circuit inputs (13, names recovered by probing the official wasm; confirmed
// by three independent participant builds):
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision (1 = APPROVE, 0 = REJECT), taskId, salt (private, random per proof)
//
// Public signals (13, in order): a salt-dependent binding hash first, then
// registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
// currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
// taskId — the platform checks the 12 task-derived signals against the
// envelope it sent and verifies the proof against the registered key.
//
// taskId mapping: the envelope's task_id is a string like "gk_24_9d1"; the
// circuit needs a field element. Default mode "keccak":
// keccak256(task_id as UTF-8) mod FIELD_PRIME — the mode a live participant
// agent used when the platform verified its practice-task proof. Fallbacks
// ("numeric", "hex") exist in case the platform rejects a proof; switch with
// GATEKEEPER_TASK_ID_MODE, no code change needed.
const crypto = require('crypto');
const path = require('path');
const snarkjs = require('snarkjs');
const { toField, keccak256ModP } = require('./field');

const WASM = path.join(__dirname, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY = path.join(__dirname, '..', 'circuits', 'gatekeeper_final.zkey');

let vkPromise = null;
function getVerificationKey() {
  if (!vkPromise) vkPromise = snarkjs.zKey.exportVerificationKey(ZKEY);
  return vkPromise;
}

function taskIdToField(taskId, mode) {
  const id = String(taskId || '');
  if (mode === 'numeric') {
    const digits = id.replace(/\D/g, '');
    return digits ? toField(BigInt(digits)) : 0n;
  }
  if (mode === 'hex') {
    const hex = id.replace(/[^0-9a-fA-F]/g, '');
    return hex ? toField(BigInt('0x' + hex)) : 0n;
  }
  return keccak256ModP([Buffer.from(id, 'utf8')]);
}

// task: the envelope input fields plus task_id. decision: 'APPROVE'|'REJECT'.
function buildInput(task, decision, taskIdMode) {
  return {
    registeredVkHash: String(task.registered_vk),
    proofVkHash: String(task.proof_vk),
    minimum: String(task.minimum),
    publicBalance: String(task.public_balance),
    expiryBlock: String(task.expiry_block),
    currentBlock: String(task.current_block),
    recipient: String(task.recipient),
    conditionRecipient: String(task.condition_recipient),
    amount: String(task.amount),
    maxTransfer: String(task.max_transfer),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdToField(task.task_id, taskIdMode).toString(),
    salt: '0x' + crypto.randomBytes(32).toString('hex'),
  };
}

// Serialize proof generation: snarkjs proving is CPU-bound; a simple queue
// keeps concurrent requests (e.g. preflight + task) from oversubscribing.
let queue = Promise.resolve();
function proveTask(task, decision, taskIdMode) {
  const run = async () => {
    const input = buildInput(task, decision, taskIdMode);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    return { proof, publicSignals };
  };
  const result = queue.then(run, run);
  queue = result.catch(() => {});
  return result;
}

async function verifyLocally(publicSignals, proof) {
  const vk = await getVerificationKey();
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

module.exports = { taskIdToField, buildInput, proveTask, verifyLocally, getVerificationKey };
