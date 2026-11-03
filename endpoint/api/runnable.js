// Runnable endpoint for the CRYPTO_TRANSFER_VERIFY comparator module.
// POST {"batch": [{"ground_truth_value": int64, "miner_value": int64, "spec": [kind, tolerance]}, ...]}
// -> 200 {"results": [{"score": bps}, ...]}. It runs the same comparator.wasm that is registered.
const fs = require('fs');
const path = require('path');

const bytes = fs.readFileSync(path.join(__dirname, '..', 'comparator.wasm'));
const ready = WebAssembly.instantiate(bytes, {}).then((r) => r.instance.exports);

const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

// Integers of 16+ digits do not survive JSON.parse as numbers, so quote them first.
function parseBatch(text) {
  const quoted = text.replace(/(?<![\w."])(-?\d{16,})(?![\w."])/g, '"$1"');
  return JSON.parse(quoted);
}

function toI64(v) {
  if (typeof v === 'number' && !Number.isSafeInteger(v)) throw new Error('number is not a safe integer');
  if (typeof v !== 'number' && typeof v !== 'string') throw new Error('not an integer');
  const b = BigInt(v);
  if (b < I64_MIN || b > I64_MAX) throw new Error('outside int64');
  return b;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    if (typeof req.body === 'string') return resolve(req.body);
    if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return resolve(JSON.stringify(req.body));
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'GET') return res.status(200).end(JSON.stringify({ ok: true, module: 'CRYPTO_TRANSFER_VERIFY comparator', batch: 'POST {"batch":[...]}' }));
  if (req.method !== 'POST') return res.status(405).end(JSON.stringify({ error: 'POST only' }));
  let body;
  try {
    body = parseBatch(await readBody(req));
  } catch (e) {
    return res.status(400).end(JSON.stringify({ error: 'invalid JSON' }));
  }
  if (!body || !Array.isArray(body.batch) || body.batch.length > 100) return res.status(400).end(JSON.stringify({ error: 'expected {"batch": [up to 100 questions]}' }));
  const x = await ready;
  const dv = () => new DataView(x.memory.buffer);
  const results = body.batch.map((q) => {
    try {
      const truth = toI64(q.ground_truth_value);
      const miner = toI64(q.miner_value);
      const kind = toI64(q.spec[0]);
      const tol = toI64(q.spec[1]);
      const p = x.imw_alloc(16);
      dv().setBigInt64(p, kind, true);
      dv().setBigInt64(p + 8, tol, true);
      const score = x.imw_score_deterministic(truth, miner, p);
      x.imw_free(p, 16);
      if (score < 0n || score > 10000n) return { error: 'module refused the input' };
      return { score: Number(score) };
    } catch (e) {
      return { error: String(e.message || e) };
    }
  });
  res.status(200).end(JSON.stringify({ results }));
};
