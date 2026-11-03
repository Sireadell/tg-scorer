const h = require('./api/runnable.js');
const call = (batch) => new Promise((resolve) => {
  const raw = '{"batch":' + batch + '}';
  const req = { method: 'POST', body: raw };
  const res = { setHeader() {}, status(c) { this.c = c; return this; }, end(s) { resolve([this.c, JSON.parse(s)]); } };
  h(req, res);
});
// reference rule in BigInt
const ref = (k, tol, t, m) => {
  const abs = (v) => (v < 0n ? -v : v);
  const d = abs(m - t);
  const lin = (e) => { if (tol <= 0n) return e === 0n ? 10000n : 0n; const w = tol * 2n; if (e >= w) return 0n; return (10000n * (w - e)) / w; };
  if (k === 1n) return lin(d);
  if (k === 2n) { let den = abs(t); if (den < 1n) den = 1n; return lin((d * 10000n) / den); }
  return m === t ? 10000n : 0n;
};
(async () => {
  const cases = [];
  const T = [1n, 7n, 12345n, 10n ** 15n, 10n ** 18n + 1n, 9n * 10n ** 18n, -(10n ** 18n), 5n];
  for (const k of [0n, 1n, 2n, 3n, 9n]) for (const tol of [0n, 1n, 50n, 800n, 10n ** 12n]) for (const t of T)
    for (const m of [t, t + 1n, t - 1n, t + t / 100n, t + t / 3n, t * 2n]) if (m <= 2n**63n-1n && m >= -(2n**63n)) cases.push([k, tol, t, m]);
  let bad = 0, n = 0;
  for (let i = 0; i < cases.length; i += 100) {
    const part = cases.slice(i, i + 100);
    const json = '[' + part.map(([k, tol, t, m]) => `{"ground_truth_value": ${t}, "miner_value": ${m}, "spec": [${k}, ${tol}]}`).join(',') + ']';
    const [code, out] = await call(json);
    if (code !== 200 || out.results.length !== part.length) { console.log('bad reply', code); process.exit(1); }
    out.results.forEach((r, j) => { n++; if (BigInt(r.score) !== ref(...part[j])) { bad++; if (bad < 5) console.log('MISMATCH', part[j], r); } });
  }
  console.log('cases', n, 'mismatches', bad);
  console.log(JSON.stringify((await call('[{"ground_truth_value": 1, "miner_value": "x", "spec": [0, 0]}]'))[1]));
})();
