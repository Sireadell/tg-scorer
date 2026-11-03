# tg-scorer

A comparator module for the Telegraph Protocol `CRYPTO_TRANSFER_VERIFY` family. It scores a miner's integer answer against the reference value, in basis points (0 to 10000), using the network's reference rule: Exact (0), AbsTol (1), RelTol (2) and PassFail (3).

## What is in here

| Path | What it is |
|---|---|
| `src/lib.rs` | The module, `no_std` Rust, no imports. Exports `memory`, `imw_alloc`, `imw_free`, `imw_score_deterministic`. |
| `transfer_verify_comparator.wasm` | The built module (2,694 bytes). |
| `endpoint/` | The runnable endpoint: takes the network's batch request and runs the same `.wasm`. |

## How it was checked

The module was run against the reference rule on 551,940 cases: every code and tolerance, truths from 1 up to 9e18, negative values, and miner values on both sides of the truth. There were 0 differences. The endpoint was checked on a further 1,150 cases, including values past 2^53 that plain JSON numbers cannot hold.

## Build

```
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

## Endpoint

`POST /runnable` with `{"batch": [{"ground_truth_value": 100, "miner_value": 101, "spec": [2, 50]}]}` returns `{"results": [{"score": 8000}]}`. Run `node endpoint/test.js` to check it locally.
