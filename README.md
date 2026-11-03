# CRYPTO_TRANSFER_VERIFY scoring module

A scoring module for the Telegraph Protocol Intent `CRYPTO_TRANSFER_VERIFY`. It rates an answer about a token transfer from 0 to 1 by checking the facts in it against the ground truth: amounts, units, addresses and who sent or received, token symbols, chain names, quoted values and whether the result is stated as success or failure.

It has no model weights and no network access, so the score is the same on every run.

## What it does

- Compares numbers by significant digits, size and unit word, so "1,000 USDC" and "1000 USDC" match but "1,000 USDC" and "10,000 USDC" do not.
- Matches each address or hash to the ground truth one for one, with its role (sender, recipient, spender), so a swapped sender and recipient is penalised.
- Penalises missing facts, invented facts, flipped outcomes and padding.
- Caps the score of answers that contain an invented full address or instruction-injection text.
- An answer identical to the ground truth scores 1.0; an empty answer scores 0.

## Interface

Exports `memory`, `alloc(size) -> ptr`, `dealloc(ptr, size)` and `rank_answer(question_ptr, question_len, ground_truth_ptr, ground_truth_len, answer_ptr, answer_len) -> f32`.

## Build

```
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

The result is about 19 KB.
