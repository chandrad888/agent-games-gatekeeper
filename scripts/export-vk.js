// Export circuits/verification_key.json from the official zkey, so proofs can
// also be verified with the snarkjs CLI:
//   npx snarkjs groth16 verify circuits/verification_key.json public.json proof.json
const fs = require('fs');
const path = require('path');
const { getVerificationKey } = require('../lib/prove');

(async () => {
  const vk = await getVerificationKey();
  const out = path.join(__dirname, '..', 'circuits', 'verification_key.json');
  fs.writeFileSync(out, JSON.stringify(vk, null, 2));
  console.log('wrote', out, `(protocol=${vk.protocol}, curve=${vk.curve}, nPublic=${vk.IC.length - 1})`);
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
