// HMAC-SHA256 signing for the Agent Games protocol.
// The platform signs every inbound envelope with the dashboard-issued secret
// ("Rotate Secret") and sends it in the `x-agent-games-signature` header.
// We verify it over the RAW request body BEFORE parsing JSON, and sign every
// response the same way (header over the raw response body).
//
// Encoding: lowercase hex HMAC-SHA256 of the raw body. This is the format a
// live, platform-verified participant agent used to pass the signed preflight.
// If the platform ever rejects it, set AGENT_GAMES_HMAC_FORMAT=sha256= to use
// the `sha256=<hex>` form instead.
const crypto = require('crypto');

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signatureFor(secret, rawBody, format) {
  const hex = hmacHex(secret, rawBody);
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

function verifySignature(secret, rawBody, headerValue, format) {
  if (!secret || !headerValue) return false;
  const expected = signatureFor(secret, rawBody, format);
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(String(headerValue), 'utf8');
  if (a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

module.exports = { hmacHex, signatureFor, verifySignature };
