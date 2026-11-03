//! CRYPTO_TRANSFER_VERIFY scoring module.
//!
//! Fact-based: pulls numbers (with the label words around them), addresses and hashes (with their
//! sender/recipient role), token symbols, chain names, quoted messages and status words out of the
//! ground truth and the miner answer. Matching facts earn marks, wrong or swapped facts are
//! punished hard. No model weights, no allocation, deterministic, microseconds per call.
#![no_std]
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

// ---------------------------------------------------------------- memory ABI

const HEAP_SIZE: usize = 1024 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0u8; HEAP_SIZE];
static mut HEAP_OFFSET: usize = 0;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn alloc(size: i32) -> i32 {
    let size = size.max(0) as usize;
    unsafe {
        let aligned = (HEAP_OFFSET + 3) & !3;
        if aligned + size > HEAP_SIZE {
            HEAP_OFFSET = 0;
        } else {
            HEAP_OFFSET = aligned;
        }
        let ptr = core::ptr::addr_of_mut!(HEAP).cast::<u8>().add(HEAP_OFFSET);
        HEAP_OFFSET += size;
        ptr as i32
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dealloc(_ptr: i32, _size: i32) {}

unsafe fn read_bytes<'a>(ptr: i32, len: i32) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize) }
}

// ---------------------------------------------------------------- small helpers

fn lower(b: u8) -> u8 {
    b.to_ascii_lowercase()
}
fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}
fn is_hex(b: u8) -> bool {
    b.is_ascii_hexdigit()
}
fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn fnv(bytes: &[u8]) -> u32 {
    let mut h: u32 = 2166136261;
    for &b in bytes {
        h ^= lower(b) as u32;
        h = h.wrapping_mul(16777619);
    }
    h
}

fn find_word(hay: &[u8], word: &[u8]) -> Option<usize> {
    let mut last = None;
    if word.is_empty() || hay.len() < word.len() {
        return None;
    }
    let mut i = 0;
    while i + word.len() <= hay.len() {
        let mut ok = true;
        for k in 0..word.len() {
            if lower(hay[i + k]) != word[k] {
                ok = false;
                break;
            }
        }
        if ok {
            let left = i == 0 || !hay[i - 1].is_ascii_alphabetic();
            let right = i + word.len() == hay.len() || !hay[i + word.len()].is_ascii_alphabetic();
            if left && right {
                last = Some(i);
            }
        }
        i += 1;
    }
    last
}

fn has_word(hay: &[u8], word: &[u8]) -> bool {
    find_word(hay, word).is_some()
}

fn contains_phrase(hay: &[u8], phrase: &[u8]) -> bool {
    if hay.len() < phrase.len() {
        return false;
    }
    let mut i = 0;
    while i + phrase.len() <= hay.len() {
        let mut ok = true;
        for k in 0..phrase.len() {
            if lower(hay[i + k]) != phrase[k] {
                ok = false;
                break;
            }
        }
        if ok {
            return true;
        }
        i += 1;
    }
    false
}

fn powi(base: f32, n: u32) -> f32 {
    let mut r = 1.0f32;
    let mut i = 0;
    while i < n {
        r *= base;
        i += 1;
    }
    r
}

const STOP: [&[u8]; 34] = [
    b"the", b"a", b"an", b"of", b"is", b"was", b"were", b"are", b"at", b"in", b"on", b"to", b"for",
    b"with", b"and", b"by", b"it", b"its", b"which", b"that", b"this", b"as", b"be", b"than", b"wei",
    b"eth", b"gwei", b"has", b"had", b"had", b"or", b"so", b"per", b"about",
];

fn is_stop(word: &[u8]) -> bool {
    for s in STOP {
        if word.len() == s.len() && word.iter().zip(s.iter()).all(|(a, b)| lower(*a) == *b) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------- facts

const MAXN: usize = 160;
const MAXI: usize = 64;
const MAXS: usize = 24;
const MAXQ: usize = 12;
const SIGLEN: usize = 32;
const CTX: usize = 8;

#[derive(Clone, Copy)]
struct Num {
    sig: [u8; SIGLEN],
    n: u8,
    mag: i16,
    ctx: [u32; CTX],
    nctx: u8,
    unit: u32, // hash of the word right after the number (wei, ETH, USDC ...), 0 if none
}
const NUM0: Num = Num { sig: [0; SIGLEN], n: 0, mag: 0, ctx: [0; CTX], nctx: 0, unit: 0 };

#[derive(Clone, Copy)]
struct Id {
    hex: [u8; 64],
    n: u8,
    role: u8, // 0 unknown, 1 sender side, 2 recipient side
}
const ID0: Id = Id { hex: [0; 64], n: 0, role: 0 };

struct Facts {
    nums: [Num; MAXN],
    nn: usize,
    ids: [Id; MAXI],
    ni: usize,
    syms: [u32; MAXS],
    ns: usize,
    quotes: [u32; MAXQ],
    nq: usize,
    chains: u32,
}

impl Facts {
    fn new() -> Facts {
        Facts {
            nums: [NUM0; MAXN],
            nn: 0,
            ids: [ID0; MAXI],
            ni: 0,
            syms: [0; MAXS],
            ns: 0,
            quotes: [0; MAXQ],
            nq: 0,
            chains: 0,
        }
    }
}

const CHAINS: [&[u8]; 14] = [
    b"ethereum", b"polygon", b"arbitrum", b"optimism", b"bnb", b"bsc", b"avalanche", b"gnosis",
    b"linea", b"scroll", b"zksync", b"mantle", b"blast", b"celo",
];

fn chain_mask(text: &[u8]) -> u32 {
    let mut m = 0u32;
    for (i, c) in CHAINS.iter().enumerate() {
        if has_word(text, c) {
            m |= 1 << i;
        }
    }
    // "base" is also the base fee, so only count it as a chain in chain-like phrases
    if let Some(p) = find_word(text, b"base") {
        let after = &text[(p + 4).min(text.len())..];
        let rest_is_fee = {
            let mut k = 0;
            while k < after.len() && after[k] == b' ' {
                k += 1;
            }
            let w = &after[k..(k + 5).min(after.len())];
            contains_phrase(w, b"fee") || contains_phrase(w, b"gas") || contains_phrase(w, b"pric")
        };
        let before = &text[p.saturating_sub(8)..p];
        let chain_like = has_word(before, b"on") || has_word(before, b"in") || has_word(before, b"to")
            || has_word(before, b"from") || has_word(before, b"of");
        if chain_like || (!rest_is_fee && p == 0) {
            m |= 1 << 20;
        }
    }
    m
}

fn add_sym(f: &mut Facts, h: u32) {
    if f.syms[..f.ns].contains(&h) || f.ns >= MAXS {
        return;
    }
    f.syms[f.ns] = h;
    f.ns += 1;
}

fn add_quote(f: &mut Facts, h: u32) {
    if f.quotes[..f.nq].contains(&h) || f.nq >= MAXQ {
        return;
    }
    f.quotes[f.nq] = h;
    f.nq += 1;
}

fn role_before(text: &[u8], at: usize) -> u8 {
    let start = at.saturating_sub(34);
    let mut w = &text[start..at];
    let mut k = w.len();
    while k > 0 {
        if w[k - 1] == b'.' && (k == w.len() || w[k] == b' ') {
            w = &w[k..];
            break;
        }
        k -= 1;
    }
    let mut best_from: Option<usize> = None;
    let mut best_to: Option<usize> = None;
    for kw in [&b"from"[..], b"sender", b"sent by", b"payer", b"originated", b"by", b"owner"] {
        if let Some(p) = find_word(w, kw) {
            best_from = Some(best_from.map_or(p, |q| q.max(p)));
        }
    }
    for kw in [&b"to"[..], b"recipient", b"receiver", b"payee", b"sent to", b"into", b"received by", b"spender"] {
        if let Some(p) = find_word(w, kw) {
            best_to = Some(best_to.map_or(p, |q| q.max(p)));
        }
    }
    match (best_from, best_to) {
        (Some(a), Some(b)) => if a > b { 1 } else { 2 },
        (Some(_), None) => 1,
        (None, Some(_)) => 2,
        _ => 0,
    }
}

fn role_after(text: &[u8], from: usize) -> u8 {
    let end = (from + 18).min(text.len());
    let w = &text[from..end];
    let first = find_word(w, b"sent").or_else(|| find_word(w, b"paid")).or_else(|| find_word(w, b"allowed"));
    let recv = find_word(w, b"received").or_else(|| find_word(w, b"got"));
    match (first, recv) {
        (Some(a), Some(b)) => if a < b { 1 } else { 2 },
        (Some(_), None) => 1,
        (None, Some(_)) => 2,
        _ => 0,
    }
}

const ALLOWED_SCALE: [i16; 5] = [0, 6, 8, 9, 18];

fn scale_ok(a: i16, b: i16) -> bool {
    let d = if a > b { a - b } else { b - a };
    ALLOWED_SCALE.contains(&d)
}

/// Content words that sit around a number: up to 3 before and 3 after, within the same clause.
fn collect_ctx(text: &[u8], start: usize, end: usize, out: &mut [u32; CTX], n: &mut u8) {
    // before
    let mut got = 0;
    let mut i = start;
    let mut scanned = 0;
    while i > 0 && got < 3 && scanned < 80 {
        let c = text[i - 1];
        if c == b';' || c == b',' {
            break;
        }
        if c == b'.' && i < text.len() && text[i] == b' ' {
            break;
        }
        if is_alnum(c) {
            let e = i;
            let mut s = i;
            while s > 0 && (is_alnum(text[s - 1]) || text[s - 1] == b',' && s >= 2 && is_digit(text[s - 2])) {
                s -= 1;
            }
            let tok = &text[s..e];
            scanned += e - s;
            i = s;
            if tok.len() >= 2 && tok[0] == b'x' && s > 0 && text[s - 1] == b'0' {
                break; // an address: stop
            }
            if tok.iter().any(|b| b.is_ascii_alphabetic()) {
                if is_clause_break(tok) {
                    break;
                }
                if tok.len() > 1 && !is_stop(tok) && !(tok.len() >= 8 && tok.iter().all(|b| is_hex(*b))) {
                    push_ctx(out, n, fnv(tok));
                    got += 1;
                }
            } else {
                break; // a different number: stop
            }
        } else {
            i -= 1;
            scanned += 1;
        }
    }
    // after
    let mut got = 0;
    let mut i = end;
    let mut scanned = 0;
    while i < text.len() && got < 3 && scanned < 80 {
        let c = text[i];
        if c == b';' || c == b',' {
            break;
        }
        if c == b'.' && i + 1 < text.len() && text[i + 1] == b' ' {
            break;
        }
        if is_alnum(c) {
            let s = i;
            while i < text.len() && (is_alnum(text[i])) {
                i += 1;
            }
            let tok = &text[s..i];
            scanned += tok.len();
            if tok.len() >= 2 && lower(tok[1]) == b'x' && tok[0] == b'0' {
                break;
            }
            if tok.iter().any(|b| b.is_ascii_alphabetic()) {
                if is_clause_break(tok) {
                    break;
                }
                if tok.len() > 1 && !is_stop(tok) {
                    push_ctx(out, n, fnv(tok));
                    got += 1;
                }
            } else {
                break;
            }
        } else {
            i += 1;
            scanned += 1;
        }
    }
}

fn is_clause_break(tok: &[u8]) -> bool {
    for w in [&b"and"[..], b"but", b"while", b"whereas"] {
        if tok.len() == w.len() && tok.iter().zip(w.iter()).all(|(a, b)| lower(*a) == *b) {
            return true;
        }
    }
    false
}

fn push_ctx(out: &mut [u32; CTX], n: &mut u8, h: u32) {
    let k = *n as usize;
    if k < CTX && !out[..k].contains(&h) {
        out[k] = h;
        *n += 1;
    }
}

fn unit_after(text: &[u8], end: usize) -> u32 {
    let mut i = end;
    if i < text.len() && text[i] == b' ' {
        i += 1;
    }
    let s = i;
    while i < text.len() && text[i].is_ascii_alphabetic() {
        i += 1;
    }
    if i - s >= 2 && i - s <= 10 {
        fnv(&text[s..i])
    } else {
        0
    }
}

fn add_num(f: &mut Facts, sig: &[u8], mag: i16, ctx: &[u32; CTX], nctx: u8, unit: u32) {
    let n = sig.len().min(SIGLEN);
    if f.nn >= MAXN {
        return;
    }
    let mut s = [0u8; SIGLEN];
    s[..n].copy_from_slice(&sig[..n]);
    f.nums[f.nn] = Num { sig: s, n: n as u8, mag, ctx: *ctx, nctx, unit };
    f.nn += 1;
}

fn add_id(f: &mut Facts, hex: &[u8], role: u8) {
    if f.ni >= MAXI {
        return;
    }
    let n = hex.len().min(64);
    let mut h = [0u8; 64];
    for i in 0..n {
        h[i] = lower(hex[i]);
    }
    f.ids[f.ni] = Id { hex: h, n: n as u8, role };
    f.ni += 1;
}

fn extract(text: &[u8], f: &mut Facts) {
    let len = text.len();
    f.chains = chain_mask(text);
    let mut i = 0;
    while i < len {
        let b = text[i];
        // quoted message
        if b == b'"' {
            let mut j = i + 1;
            while j < len && text[j] != b'"' && j - i < 90 {
                j += 1;
            }
            if j < len && text[j] == b'"' && j > i + 1 {
                add_quote(f, fnv(&text[i + 1..j]));
                i = j + 1;
                continue;
            }
        }
        // 0x... identifier
        if b == b'0' && i + 2 < len && lower(text[i + 1]) == b'x' && is_hex(text[i + 2]) {
            let mut j = i + 2;
            while j < len && is_hex(text[j]) {
                j += 1;
            }
            let run = j - (i + 2);
            if run >= 6 {
                let mut role = role_after(text, j);
                if role == 0 && run <= 42 {
                    role = role_before(text, i);
                }
                add_id(f, &text[i + 2..j], role);
            }
            i = j;
            continue;
        }
        // upper-case token symbol such as USDC, WETH, OP
        if b.is_ascii_uppercase() && (i == 0 || !is_alnum(text[i - 1])) {
            let mut j = i;
            while j < len && (text[j].is_ascii_uppercase() || is_digit(text[j])) {
                j += 1;
            }
            let upper = text[i..j].iter().filter(|c| c.is_ascii_uppercase()).count();
            if upper >= 2 && j - i <= 10 && (j == len || !text[j].is_ascii_alphabetic()) {
                add_sym(f, fnv(&text[i..j]));
            }
            if j > i {
                i = j;
                continue;
            }
        }
        if is_digit(b) {
            if i > 0 && text[i - 1].is_ascii_alphabetic() {
                while i < len && (is_digit(text[i]) || text[i].is_ascii_alphabetic()) {
                    i += 1;
                }
                continue;
            }
            let mut digits = [0u8; 80];
            let mut nd = 0usize;
            let mut int_digits = 0i32;
            let mut seen_dot = false;
            let mut j = i;
            while j < len {
                let c = text[j];
                if is_digit(c) {
                    if nd < digits.len() {
                        digits[nd] = c;
                        nd += 1;
                    }
                    if !seen_dot {
                        int_digits += 1;
                    }
                    j += 1;
                } else if c == b',' && !seen_dot && j + 3 < len
                    && is_digit(text[j + 1]) && is_digit(text[j + 2]) && is_digit(text[j + 3])
                    && (j + 4 >= len || !is_digit(text[j + 4]))
                {
                    j += 1;
                } else if c == b'.' && !seen_dot && j + 1 < len && is_digit(text[j + 1]) {
                    seen_dot = true;
                    j += 1;
                } else {
                    break;
                }
            }
            let mut s = 0usize;
            let mut lead_zero_after_dot = 0i32;
            let mut consumed_int = int_digits;
            while s < nd && digits[s] == b'0' {
                if consumed_int > 0 {
                    consumed_int -= 1;
                } else {
                    lead_zero_after_dot += 1;
                }
                s += 1;
            }
            let mut e = nd;
            while e > s && digits[e - 1] == b'0' {
                e -= 1;
            }
            if e > s {
                let mag: i32 = if consumed_int > 0 { consumed_int } else { -lead_zero_after_dot };
                let mut ctx = [0u32; CTX];
                let mut nctx = 0u8;
                collect_ctx(text, i, j, &mut ctx, &mut nctx);
                add_num(f, &digits[s..e], mag as i16, &ctx, nctx, unit_after(text, j));
            }
            i = j.max(i + 1);
            continue;
        }
        i += 1;
    }
}

// ---------------------------------------------------------------- matching

fn num_match(a: &Num, t: &Num) -> u8 {
    let (an, tn) = (a.n as usize, t.n as usize);
    if an == tn && a.sig[..an] == t.sig[..tn] {
        if a.mag == t.mag || (an >= 3 && scale_ok(a.mag, t.mag)) {
            return 2;
        }
        return 0;
    }
    if an >= 3 && an + 2 <= tn && a.sig[..an] == t.sig[..an] {
        if a.mag == t.mag || scale_ok(a.mag, t.mag) {
            return 1;
        }
    }
    0
}

fn ctx_overlap(a: &Num, b: &Num) -> bool {
    for i in 0..a.nctx as usize {
        if b.ctx[..b.nctx as usize].contains(&a.ctx[i]) {
            return true;
        }
    }
    false
}

/// Did an earlier, still unmatched number already carry these same digits (another unit form)?
fn same_sig_earlier(nums: &[Num], idx: usize, matched: &[bool]) -> bool {
    for j in 0..idx {
        if !matched[j] && nums[j].n == nums[idx].n && nums[j].sig[..nums[j].n as usize] == nums[idx].sig[..nums[idx].n as usize] {
            return true;
        }
    }
    false
}

fn id_match(a: &Id, t: &Id) -> bool {
    let (an, tn) = (a.n as usize, t.n as usize);
    if an == tn {
        return a.hex[..an] == t.hex[..tn];
    }
    if an >= 6 && an < tn {
        return a.hex[..an] == t.hex[..an];
    }
    false
}

fn word_overlap(truth: &[u8], ans: &[u8]) -> f32 {
    fn words(text: &[u8], out: &mut [u32; 192]) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < text.len() {
            if text[i].is_ascii_alphabetic() {
                let s = i;
                while i < text.len() && text[i].is_ascii_alphabetic() {
                    i += 1;
                }
                if i - s >= 3 {
                    let h = fnv(&text[s..i]);
                    if n < out.len() && !out[..n].contains(&h) {
                        out[n] = h;
                        n += 1;
                    }
                }
            } else {
                i += 1;
            }
        }
        n
    }
    let mut tw = [0u32; 192];
    let mut aw = [0u32; 192];
    let tn = words(truth, &mut tw);
    let an = words(ans, &mut aw);
    if tn == 0 || an == 0 {
        return 0.0;
    }
    let mut hit = 0;
    for w in &aw[..an] {
        if tw[..tn].contains(w) {
            hit += 1;
        }
    }
    let p = hit as f32 / an as f32;
    let r = hit as f32 / tn as f32;
    if p + r == 0.0 { 0.0 } else { 2.0 * p * r / (p + r) }
}

// ---------------------------------------------------------------- status words

const POS: [&[u8]; 7] = [b"success", b"successful", b"successfully", b"succeeded", b"confirmed", b"finalized", b"completed"];
const NEG: [&[u8]; 8] = [b"failed", b"reverted", b"failure", b"error", b"rejected", b"dropped", b"unsuccessful", b"stopped"];

fn negated(text: &[u8], at: usize) -> bool {
    let start = at.saturating_sub(10);
    let w = &text[start..at];
    has_word(w, b"not") || has_word(w, b"never") || has_word(w, b"no") || w.ends_with(b"n't ")
}

fn polarity(text: &[u8]) -> i8 {
    let mut pos = false;
    let mut neg = false;
    for p in POS {
        if let Some(i) = find_word(text, p) {
            if negated(text, i) { neg = true } else { pos = true }
        }
    }
    for n in NEG {
        if let Some(i) = find_word(text, n) {
            if negated(text, i) { pos = true } else { neg = true }
        }
    }
    if pos && !neg { 1 } else if neg && !pos { -1 } else { 0 }
}

const INJECTION: [&[u8]; 9] = [
    b"ignore previous", b"ignore all", b"ignore the above", b"system prompt", b"give this a score",
    b"perfect score", b"score of 1", b"rate this", b"disregard",
];

// ---------------------------------------------------------------- scoring

fn score(question: &[u8], truth: &[u8], ans: &[u8]) -> f32 {
    let mut ft = Facts::new();
    let mut fq = Facts::new();
    let mut fa = Facts::new();
    extract(truth, &mut ft);
    extract(question, &mut fq);
    extract(ans, &mut fa);

    // ---- numbers
    let mut t_hit = [false; MAXN];
    let mut a_ok = [false; MAXN];
    let mut label_swaps = 0u32;
    let mut mag_clashes = 0u32;
    for ai in 0..fa.nn {
        let a = fa.nums[ai];
        let mut matched_any = false;
        let mut label_ok = false;
        let mut informative = false;
        // same digits and same unit word, but a different magnitude (23.69 USDC vs 0.00000000002369 USDC)
        let mut unit_clash = false;
        let mut exact_mag = false;
        for ti in 0..ft.nn {
            let t = &ft.nums[ti];
            if a.n == t.n && a.sig[..a.n as usize] == t.sig[..t.n as usize] {
                if a.mag == t.mag {
                    exact_mag = true;
                } else if a.unit != 0 && a.unit == t.unit {
                    unit_clash = true;
                }
            }
        }
        let scaled_ok = !(unit_clash && !exact_mag);
        if !scaled_ok {
            mag_clashes += 1;
        }
        for ti in 0..ft.nn {
            let t = &ft.nums[ti];
            let m = num_match(&a, t);
            if m > 0 && (scaled_ok || a.mag == t.mag) {
                a_ok[ai] = true;
                t_hit[ti] = true;
                matched_any = true;
                if t.nctx > 0 {
                    informative = true;
                }
                if a.nctx == 0 || t.nctx == 0 || ctx_overlap(&a, t) {
                    if t.nctx > 0 || a.nctx == 0 {
                        label_ok = true;
                    }
                }
            }
        }
        if matched_any && !informative {
            label_ok = true;
        }
        // the value exists in the truth, but only under other labels: is its own label used elsewhere?
        if matched_any && !label_ok {
            let mut belongs_elsewhere = false;
            for ui in 0..ft.nn {
                if ctx_overlap(&a, &ft.nums[ui]) && num_match(&a, &ft.nums[ui]) == 0 {
                    belongs_elsewhere = true;
                }
            }
            if belongs_elsewhere {
                label_swaps += 1;
            }
        }
        if !a_ok[ai] {
            for qi in 0..fq.nn {
                if num_match(&a, &fq.nums[qi]) > 0 {
                    a_ok[ai] = true;
                    break;
                }
            }
        }
    }
    let (mut t_unmatched, mut t_strong, mut t_total) = (0u32, 0u32, 0u32);
    let (mut a_unmatched, mut a_strong) = (0u32, 0u32);
    for ti in 0..ft.nn {
        let mut in_q = false;
        for qi in 0..fq.nn {
            if num_match(&fq.nums[qi], &ft.nums[ti]) == 2 {
                in_q = true;
                break;
            }
        }
        if in_q {
            continue;
        }
        t_total += 1;
        // the other unit form of a value the answer already gave (wei given, ETH form left out)
        let mut alt_form_hit = false;
        for tj in 0..ft.nn {
            if t_hit[tj] && tj != ti && ft.nums[tj].n == ft.nums[ti].n
                && ft.nums[tj].sig[..ft.nums[tj].n as usize] == ft.nums[ti].sig[..ft.nums[ti].n as usize]
                && ft.nums[tj].unit != ft.nums[ti].unit
            {
                alt_form_hit = true;
            }
        }
        if !t_hit[ti] && !alt_form_hit && !same_sig_earlier(&ft.nums, ti, &t_hit) {
            t_unmatched += 1;
            if ft.nums[ti].n >= 3 {
                t_strong += 1;
            }
        }
    }
    for ai in 0..fa.nn {
        // a wrong value shown twice (wei and ETH) is one wrong fact
        if !a_ok[ai] && !same_sig_earlier(&fa.nums, ai, &a_ok) {
            a_unmatched += 1;
            if fa.nums[ai].n >= 3 {
                a_strong += 1;
            }
        }
    }
    let conflicts = t_unmatched.min(a_unmatched);
    let conflicts_strong = conflicts.min(t_strong.max(a_strong));
    let conflicts_weak = conflicts - conflicts_strong;
    let missing = t_unmatched - conflicts;
    let extra = a_unmatched - conflicts;

    let mut s = 1.0f32;
    s *= powi(0.28, conflicts_strong.min(4));
    s *= powi(0.42, conflicts_weak.min(3));
    s *= powi(0.82, missing.min(6));
    let extra_strong = a_strong.saturating_sub(conflicts).min(extra);
    s *= powi(0.45, extra_strong.min(6));
    s *= powi(0.85, (extra - extra_strong).min(6));
    s *= powi(0.30, label_swaps.min(3));
    s *= powi(0.30, mag_clashes.min(2));
    if t_total > 0 {
        let cov = (t_total - t_unmatched) as f32 / t_total as f32;
        s *= 0.15 + 0.85 * cov;
    }

    // ---- identifiers, with their roles
    let mut fabricated_full = false;
    let mut fabricated_part = 0u32;
    let mut role_swaps = 0u32;
    let mut id_missing = 0u32;
    let mut id_total = 0u32;
    let mut used = [false; MAXI];
    let mut id_short = 0u32;
    let mut role_extra = 0u32;
    for ai in 0..fa.ni {
        let a = fa.ids[ai];
        let mut supported = false;
        for ti in 0..ft.ni {
            if id_match(&a, &ft.ids[ti]) || id_match(&ft.ids[ti], &a) {
                supported = true;
            }
        }
        if !supported {
            for qi in 0..fq.ni {
                if id_match(&a, &fq.ids[qi]) || id_match(&fq.ids[qi], &a) {
                    supported = true;
                }
            }
        }
        if !supported {
            if a.n >= 40 { fabricated_full = true } else { fabricated_part += 1 }
        }
    }
    for ti in 0..ft.ni {
        let t = ft.ids[ti];
        let mut in_q = false;
        for qi in 0..fq.ni {
            if id_match(&fq.ids[qi], &t) {
                in_q = true;
            }
        }
        if in_q {
            continue;
        }
        id_total += 1;
        // one-to-one: an answer occurrence can vouch for only one truth occurrence
        let mut taken = None;
        let mut taken_any = None;
        for ai in 0..fa.ni {
            if used[ai] || !id_match(&fa.ids[ai], &t) {
                continue;
            }
            if taken_any.is_none() {
                taken_any = Some(ai);
            }
            let r = fa.ids[ai].role;
            if r == 0 || t.role == 0 || r == t.role {
                taken = Some(ai);
                break;
            }
        }
        if let Some(ai) = taken {
            used[ai] = true;
        } else if let Some(ai) = taken_any {
            used[ai] = true;
            role_swaps += 1;
        } else {
            // every answer mention of this id is already spoken for: one mention too few
            let mut seen_before = false;
            for ai in 0..fa.ni {
                if id_match(&fa.ids[ai], &t) {
                    seen_before = true;
                }
            }
            if seen_before {
                id_short += 1;
            } else {
                id_missing += 1;
            }
        }
    }
    // an id shown in a role the truth never gives it (a recipient that was only ever a sender)
    for ai in 0..fa.ni {
        let a = fa.ids[ai];
        if used[ai] || a.role == 0 {
            continue;
        }
        let mut known = false;
        let mut role_known = false;
        for ti in 0..ft.ni {
            if id_match(&a, &ft.ids[ti]) {
                known = true;
                if ft.ids[ti].role == 0 || ft.ids[ti].role == a.role {
                    role_known = true;
                }
            }
        }
        if known && !role_known {
            role_extra += 1;
        }
    }
    s *= powi(0.80, id_short.min(3));
    s *= powi(0.35, role_extra.min(2));
    s *= powi(0.30, role_swaps.min(3));
    s *= powi(0.55, fabricated_part.min(3));
    s *= powi(0.90, id_missing.min(4));
    if id_total > 0 {
        let cov = (id_total - id_missing) as f32 / id_total as f32;
        s *= 0.3 + 0.7 * cov;
    }

    // ---- token symbols
    let mut sym_t = 0u32;
    let mut sym_a = 0u32;
    for ti in 0..ft.ns {
        let h = ft.syms[ti];
        if !fa.syms[..fa.ns].contains(&h) && !fq.syms[..fq.ns].contains(&h) {
            sym_t += 1;
        }
    }
    for ai in 0..fa.ns {
        let h = fa.syms[ai];
        if !ft.syms[..ft.ns].contains(&h) && !fq.syms[..fq.ns].contains(&h) {
            sym_a += 1;
        }
    }
    let sym_conf = sym_t.min(sym_a);
    s *= powi(0.30, sym_conf.min(2));
    s *= powi(0.92, (sym_t - sym_conf).min(3));
    s *= powi(0.92, (sym_a - sym_conf).min(3));

    // ---- chain names
    let truth_chains = ft.chains | fq.chains;
    if ft.chains != 0 && fa.chains != 0 && (fa.chains & !truth_chains) != 0 {
        s *= 0.30;
    }

    // ---- quoted messages
    let mut q_missing = 0u32;
    let mut q_extra = 0u32;
    for qi in 0..ft.nq {
        if !fa.quotes[..fa.nq].contains(&ft.quotes[qi]) {
            q_missing += 1;
        }
    }
    for qi in 0..fa.nq {
        if !ft.quotes[..ft.nq].contains(&fa.quotes[qi]) && !fq.quotes[..fq.nq].contains(&fa.quotes[qi]) {
            q_extra += 1;
        }
    }
    s *= powi(0.35, q_extra.min(2));
    s *= powi(0.60, q_missing.min(2));

    // ---- status words
    let (pt, pa) = (polarity(truth), polarity(ans));
    if pt != 0 && pa != 0 && pt != pa {
        s *= 0.25;
    }

    // ---- wording
    let wo = word_overlap(truth, ans);
    let hard = ft.nn + ft.ni + ft.nq;
    let mut out = if hard > 0 { s * (0.88 + 0.12 * wo) } else { s * (0.2 + 0.8 * wo) };

    if fabricated_full && out > 0.20 {
        out = 0.20;
    }
    let mut inj = 0usize;
    while inj < INJECTION.len() {
        let p = INJECTION[inj];
        inj += 1;
        if contains_phrase(ans, p) && !contains_phrase(truth, p) && !contains_phrase(question, p) {
            out = out.min(0.10);
        }
    }
    if out < 0.0 { 0.0 } else if out > 1.0 { 1.0 } else { out }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rank_answer(
    q_ptr: i32,
    q_len: i32,
    gt_ptr: i32,
    gt_len: i32,
    ma_ptr: i32,
    ma_len: i32,
) -> f32 {
    unsafe {
        let ans = read_bytes(ma_ptr, ma_len);
        if ans.iter().all(|b| b.is_ascii_whitespace()) {
            return 0.0;
        }
        let q = read_bytes(q_ptr, q_len);
        let t = read_bytes(gt_ptr, gt_len);
        if ans == t {
            return 1.0;
        }
        score(q, t, ans)
    }
}
