# Commutative-Quasigroup-Actions
A Proof-of-Concept implementation of Commutative Actions based on m-ary Quasigroups and its use for a Key Exchange Protocol similar to Diffie-Hellman key exchange

This repository provides a **research proof-of-concept** implementation of a key exchange based on a **commutative action**
constructed from structured quasigroup/Latin-style operations in a **2-adic regime**.

> ⚠️ **Research / PoC disclaimer**: This code is *not* production-ready and provides **no authentication**.
> Like unauthenticated Diffie–Hellman, it is vulnerable to man-in-the-middle attacks unless combined with an authentication layer.

## Files

- `cqa_kex_poc.py` — PoC implementation with KDF and shared-secret printing.
- `params.py` — draft tier profiles (128/192/256-bit; rounds 2 and 4 variants).

## Quick start

### Run a toy configuration

```bash
python cqa_kex_poc.py --base-w 32 --tweak 0 --delta 2 --degree 3 --arity 3 --rounds 2 --family-seed 12345
```

### Run a draft tier profile

Example: 128-bit tier (rounds=2)

```bash
python cqa_kex_poc.py --base-w 512 --tweak 0 --delta 2 --degree 3 --arity 3 --rounds 2 --family-seed 12345
```

Example: 128-bit tier (rounds=4)

```bash
python cqa_kex_poc.py --base-w 512 --tweak 2 --delta 2 --degree 3 --arity 3 --rounds 4 --family-seed 12345
```

## Notes on shared-secret hex output

The PoC prints the shared secret in both **little-endian (LE)** and **big-endian (BE)** hex.
In a 2-adic regime, low bits can be **frozen** (common suffix). If you serialize in **little-endian**, those frozen low bits
appear at the **start** of the hex string, which can look ``non-random''. The derived session key should still look pseudorandom
because it is output by the KDF.

## License

The code is released under the **MIT License**. You may use, copy, and modify it, provided you keep the copyright and license notice.

## Authon/date

Danilo Gligoroski / 10 March 2026
