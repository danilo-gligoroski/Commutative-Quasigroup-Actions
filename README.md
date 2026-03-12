# Research PoC for a 2D commutative quasigroup-action key exchange in a 2-adic regime

This repository contains a **standalone Python script** proof-of-concept for a **2D Commutative Quasigroup Action (CQA) key exchange** in a 2-adic regime.

The main script is:

- `cqa_2d_kex.py`

It is self-contained and no longer imports helper code from `cqa_kex_poc.py`. Instead, the scalar CQA PoC machinery has been inlined and then lifted to a 2D swap-family operator action.

---

## Status and scope

**This is a research prototype / PoC, not a secure production implementation.**

In particular:

- it is useful for experimentation with commutative-action behavior,
- it includes diagnostics for obvious 1D-collapse / degeneracy modes,
- it includes a simple transcript-bound HKDF session-key derivation,
- but it does **not** provide authentication and should not be treated as secure KEX.

---

## Main idea

The script starts from the scalar 2-adic CQA family and lifts it to a 2D vector-state action.

1. Work over `Z / 2^w Z` using the same conservative scalar family generation as the scalar CQA PoC.
2. Reserve one public slot for a tag `tau`.
3. For each tag in `{tau0, tau1}`, derive a scalar coefficient using a reduced scalar action:
   - `lambda0(K) = T_{K,tau0}(xseed0)`
   - `lambda1(K) = T_{K,tau1}(xseed1)`
4. Form the commuting 2x2 operator
   - `M_K = lambda0(K) * I + lambda1(K) * S`
   - with `S = [[0,1],[1,0]]`
5. Use a public base vector `G = (g1, g2)`.
6. Publish `A_pub = M_A^rounds(G)` and `B_pub = M_B^rounds(G)`.
7. Compute the shared secret as
   - `ss = M_A^rounds(B_pub) = M_B^rounds(A_pub)`
   when commutativity holds.
8. Derive a session key from the 2D shared secret and the public transcript `(A_pub || B_pub)` using HKDF-style HMAC-SHA3-256.

---

## Why this version is useful

Compared with the earlier design-scaffold versions:

- it is **standalone**,
- it preserves the current comments and structure of the 2D design,
- it includes the **Campaign 3 perturbation hook** via `xseed0` and `xseed1`,
- and it keeps the diagnostic functions for:
  - commutativity,
  - swap-basis collapse,
  - and the obvious `Delta(G)`-based recovery condition.

---

## Files

- `cqa_2d_kex.py` — standalone 2D CQA KEX PoC
- `README.md` — this file

---

## Requirements

- Python 3.10+ recommended
- No third-party dependencies

The script only uses the Python standard library.

---

## Command-line usage

Show help:

```bash
python3 cqa_2d_kex.py --help
```

### 1) Reproduce the anchored design (`xseed0 = xseed1 = 1`)

```bash
python3 cqa_2d_kex.py         --base-w 128         --tweak 0         --delta 2         --degree 3         --arity 4         --rounds 2         --scalar-rounds 1         --family-seed 12345         --tau0 1         --tau1 3         --xseed0 1         --xseed1 1         --g1 5         --g2 7         --seedA 111         --seedB 222
```

### 2) Run a Campaign 3-style perturbed instance

```bash
python3 cqa_2d_kex.py         --base-w 128         --tweak 0         --delta 2         --degree 3         --arity 4         --rounds 2         --scalar-rounds 1         --family-seed 12345         --tau0 17         --tau1 91         --xseed0 123456789         --xseed1 987654321         --g1 5         --g2 7         --seedA 111         --seedB 222
```

### 3) Let the script choose fresh random secret seeds

If you omit `--seedA` and `--seedB`, the script will draw fresh random 64-bit seeds:

```bash
python3 cqa_2d_kex.py         --base-w 256         --tweak 0         --delta 2         --degree 3         --arity 4         --rounds 2         --scalar-rounds 1         --family-seed 12345         --tau0 1         --tau1 3         --xseed0 1         --xseed1 1         --g1 9         --g2 11
```

---

## What the script prints

A typical run prints:

- the main parameter set,
- the chosen tags and x-seeds,
- the public base vector `G`,
- the two public keys,
- the two copies of the shared secret,
- a commutativity check,
- a transcript-bound session key,
- degeneracy diagnostics in the swap basis,
- and the direct `Delta(G)` recovery diagnostic.

---

## Notes on the current design

### Public x-seeds

The current version uses **public** `xseed0` and `xseed1` in coefficient extraction:

- `lambda0(K) = T_{K,tau0}(xseed0)`
- `lambda1(K) = T_{K,tau1}(xseed1)`

Setting both to `1` recovers the earlier anchored design.

### Commutativity bugfix

The script uses the corrected semantics for `rounds >= 2`:

- public key: `M_K^rounds(G)`
- shared secret: `M_K^rounds(peer_pk)`

This fixes the earlier mismatch where public keys were computed at depth 1 while shared-secret derivation used depth `rounds`.

### Session key derivation

The raw shared secret is a 2D vector over `Z / 2^w Z`.
A session key is derived from:

- serialized shared secret,
- and transcript context `(A_pub || B_pub)`

using HKDF-style HMAC-SHA3-256.

---

## Security warning

This repository is for **research and experimentation only**.

In particular:

- there is no authentication,
- the obvious one-public-vector recovery condition may still apply for some choices of `G`,
- and passing the built-in commutativity / degeneracy checks does **not** imply cryptographic security.

---

## License

MIT License.

See the header of `cqa_2d_kex.py` for the license text.

--

## Author/date

Danilo Gligoroski / 12 March 2026
