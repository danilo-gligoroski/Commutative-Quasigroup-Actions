#!/usr/bin/env python3
"""
CQA KEX PoC — Commutative Quasigroup Action Key Exchange (general k-ary)

This is a minimal, self-contained proof-of-concept for the CQA construction
described in the paper:

    "Commutative m-ary Quasigroup Actions in a 2-adic Regime:
     A CSIDH-like Commutative-Action Candidate and a Key Exchange Protocol"
     (Danilo Gligoroski, NTNU, May 2026)

It implements:
  • LegacySampler with explicit even/odd coefficient constraints (G even, A/B odd)
  • PolyOddDegree (Horner evaluation modulo 2^proj_w)
  • Family with cyclic m-ary wiring (build_cyclic_args + macro_step)
  • act() = R rounds of macro-steps
  • Full KEX: keygen → pubkey → shared_secret with commutativity verification

The construction is proven to commute in the 2-adic regime when:
  - g is even (default g=2, the smallest even positive integer — guarantees good mixing)
  - secret components are odd
  - polynomials have odd degree with compatible parity

Extensive 2D parameter sweeps (base_w ∈ {32,36,40,44,48}, v_2(g) ∈ 1..18,
rounds ∈ 2..16, degree 3 and 9) confirm:
  - |image(Apub)| and |image(ssA)| are always exact powers of 2
  - they shrink exponentially with v_2(g)
  - for all safe parameters (base_w ≥ 40 or v_2(g) ≥ 3) we have
    Apub ∩ ssA = ∅ (perfect algebraic separation)

Run (clean mode — recommended):
    python3 cqa_kex_poc_general_k.py --base-w 512 --family-seed 42 --arity 4 --rounds 2
or:
    python3 cqa_kex_poc_general_k.py --base-w 512 --family-seed 42 --arity 4 --degree 9 --rounds 85

Run (full numerical trace for debugging):
    python3 cqa_kex_poc_general_k.py --base-w 512 --family-seed 42 --arity 4 --rounds 2 --verbose

The computation is 100% identical in both modes (same wiring, same everything).
Only extra print statements are added when --verbose is used.
"""

# SPDX-License-Identifier: MIT
#
# Copyright (c) 2026 Danilo Gligoroski
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import random
from dataclasses import dataclass
from typing import List, Optional


def fmt(x: int, n: int = 20) -> str:
    """Pretty-print huge integers: first n digits + ... + last 8 digits"""
    s = str(x)
    if len(s) <= n + 10:
        return s
    return f"{s[:n]}...{s[-8:]}"

def int_to_le_bytes(x: int, length: int) -> bytes:
    return int(x).to_bytes(length, 'little', signed=False)

def le_bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little', signed=False)

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha3_256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b''
    t = b''
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha3_256).digest()
        out += t
        counter += 1
    return out[:length]


@dataclass
class LegacySampler:
    base_w: int
    proj_w: int
    delta: int
    rng: random.Random

    @property
    def MOD(self) -> int:
        return 1 << self.proj_w

    @property
    def SHIFT_EXP(self) -> int:
        return (self.base_w // 2) - self.delta

    @property
    def SHIFTLeft(self) -> int:
        return 1 << self.SHIFT_EXP

    def r_bits(self) -> int:
        return max(1, self.proj_w - self.SHIFT_EXP - 1)

    def even_coeff(self) -> int:
        r = self.rng.getrandbits(self.r_bits())
        return (2 * (self.SHIFTLeft * r)) % self.MOD

    def odd_coeff(self) -> int:
        r = self.rng.getrandbits(self.r_bits())
        return (2 * (self.SHIFTLeft * r) + 1) % self.MOD

    def structured_odd(self) -> int:
        return self.odd_coeff()


@dataclass
class PolyOddDegree:
    coeffs: List[int]
    MOD: int

    def eval(self, x: int) -> int:
        x %= self.MOD
        acc = 0
        for a in reversed(self.coeffs):
            acc = (acc * x + a) % self.MOD
        return acc


def sample_poly(s: LegacySampler, degree: int) -> PolyOddDegree:
    if degree < 1 or (degree % 2) == 0:
        raise ValueError('degree must be positive odd')
    coeffs = [s.even_coeff() for _ in range(degree + 1)]
    coeffs[1] = s.odd_coeff()
    if (sum(coeffs) & 1) == 0:
        coeffs[0] ^= 1
    return PolyOddDegree(coeffs=coeffs, MOD=s.MOD)


@dataclass
class Family:
    proj_w: int
    arity: int
    polys: List[PolyOddDegree]
    g: int

    @property
    def MOD(self) -> int:
        return 1 << self.proj_w

    def f(self, xs: List[int]) -> int:
        assert len(xs) == self.arity
        acc = 1
        for P, x in zip(self.polys, xs):
            val = P.eval(x)
            acc = (acc * val) % self.MOD
        return acc


def build_cyclic_args(base: List[int], current: int, step: int, k: int) -> List[int]:
    m = len(base)
    rotated = base[step % m:] + base[:step % m]
    pos = k - 1 - step
    args = rotated[:pos] + [current] + rotated[pos:]
    return args


def macro_step(fam: Family, key: List[int], x: int) -> int:
    MOD = fam.MOD
    K = [k % MOD for k in key]
    current = x % MOD
    k = fam.arity
    for step in range(k):
        args = build_cyclic_args(K, current, step, k)
        val = fam.f(args)
        current = val
    return current


def act(fam: Family, key: List[int], x: int, rounds: int) -> int:
    out = x % fam.MOD
    for _ in range(rounds):
        out = macro_step(fam, key, out)
    return out


@dataclass
class Params:
    base_w: int
    tweak: int
    delta: int
    degree: int
    arity: int
    rounds: int
    family_seed: int

    @property
    def proj_w(self) -> int:
        return self.base_w + self.tweak

    @property
    def pk_len(self) -> int:
        return (self.proj_w + 7) // 8


def setup(params: Params, g_override: Optional[int] = None) -> Family:
    rng = random.Random(params.family_seed)
    s = LegacySampler(base_w=params.base_w, proj_w=params.proj_w,
                      delta=params.delta, rng=rng)
    polys = [sample_poly(s, params.degree) for _ in range(params.arity)]
    if g_override is None:
        g = 2          # <--- IMPORTANT: default to the smallest even integer
    else:
        g = g_override % (1 << params.proj_w)
        if g % 2 == 1:
            g = (g + 1) % (1 << params.proj_w)
    return Family(proj_w=params.proj_w, arity=params.arity, polys=polys, g=g)


def keygen(params: Params, seed: int) -> List[int]:
    rng = random.Random(seed)
    s = LegacySampler(base_w=params.base_w, proj_w=params.proj_w,
                      delta=params.delta, rng=rng)
    return [s.structured_odd() for _ in range(params.arity - 1)]


def pubkey(params: Params, fam: Family, sk: List[int]) -> int:
    return act(fam, sk, fam.g, params.rounds)


def shared_secret(params: Params, fam: Family, sk: List[int], peer_pk: int) -> int:
    return act(fam, sk, peer_pk, params.rounds)


def demo(params: Params, out_len: int, *, verbose: bool = False,
         g_override: Optional[int] = None,
         A_override: Optional[List[int]] = None,
         B_override: Optional[List[int]] = None,
         seedA: Optional[int] = None,
         seedB: Optional[int] = None) -> None:

    fam = setup(params, g_override=g_override)
    A = _resolve_secret_tuple(params, 'A', A_override, seedA)
    B = _resolve_secret_tuple(params, 'B', B_override, seedB)

    if verbose:
        # === FULL VERBOSE TRACE (for debugging) ===
        print("\n=== SETUP ===")
        print(f"g = {fmt(fam.g)} (even)")
        for i, p in enumerate(fam.polys):
            print(f"poly[{i}].coeffs (first 3) = {p.coeffs[:3]}...")

        print(f"\n=== SECRETS ===")
        print(f"A = {[fmt(v) for v in A]}")
        print(f"B = {[fmt(v) for v in B]}")

        print("\nComputing Apub")
        Apub = pubkey(params, fam, A)
        print("\nComputing Bpub")
        Bpub = pubkey(params, fam, B)

        print(f"\n=== FINAL RESULTS ===")
        print(f"Apub = {fmt(Apub)}")
        print(f"Bpub = {fmt(Bpub)}")
        print(f"Apub == Bpub ? {Apub == Bpub}")

        ssA = shared_secret(params, fam, A, Bpub)
        ssB = shared_secret(params, fam, B, Apub)
        print(f"shared secret (LE hex) = {int_to_le_bytes(ssA, params.pk_len).hex()}")
        print(f"commutativity check: {ssA == ssB}")
        return

    # === CLEAN PRODUCTION OUTPUT ===
    Apub = pubkey(params, fam, A)
    Bpub = pubkey(params, fam, B)

    ssA = shared_secret(params, fam, A, Bpub)
    ssB = shared_secret(params, fam, B, Apub)

    # Derive a short session key via HKDF (same as old PoC)
    prk = hkdf_extract(b'CQA-KEX', int_to_le_bytes(ssA, params.pk_len))
    session_key = hkdf_expand(prk, b'CQA session key', 32)

    print("CQA KEX PoC")
    print(f"  params: base_w={params.base_w}, tweak={params.tweak} (proj_w={params.proj_w}), "
          f"delta={params.delta}, degree={params.degree}, arity={params.arity}, rounds={params.rounds}")
    print(f"  public key bytes: {params.pk_len}  (KEX transcript: {2*params.pk_len} bytes + optional KDF context)")
    print(f"  A_pub = {Apub:0{params.pk_len*2}x}")
    print(f"  B_pub = {Bpub:0{params.pk_len*2}x}")
    print(f"  commutativity check: {ssA == ssB}")
    print(f"  shared secret (LE hex): {int_to_le_bytes(ssA, params.pk_len).hex()}")
    print(f"  shared secret (BE hex): {int_to_le_bytes(ssA, params.pk_len)[::-1].hex()}")
    print(f"  session key match: {ssA == ssB}")
    print(f"  session key (hex): {session_key.hex()}")
    print()
    print("  note 1: in a 2-adic regime, the low bits can be \"frozen\" (common suffix), "
          "so in little-endian those frozen low bits appear at the start of the hex string.")
    print("  and we can use that property to compress the public keys to ~1/2 of their size. ")
    print()
    print("  note 2: This is a research project. Not all parameters give always a perfect commutative action.")
    print("  Example: try several times to execute the following command:")
    print("  python3 cqa_kex_poc_general_k.py --base-w 512 --family-seed 42 --arity 7 --degree 13 --rounds 85")



def _resolve_secret_tuple(params: Params, label: str,
                          override: Optional[List[int]],
                          seed: Optional[int]) -> List[int]:
    if override is not None:
        if len(override) != params.arity - 1:
            raise ValueError(f'{label} override length must be {params.arity - 1}')
        MOD = 1 << params.proj_w
        return [x % MOD for x in override]
    if seed is None:
        seed = int.from_bytes(os.urandom(8), 'little')
    return keygen(params, seed)


def main() -> None:
    ap = argparse.ArgumentParser(
        description='CQA KEX PoC — Commutative Quasigroup Action Key Exchange (general k-ary)'
    )
    ap.add_argument('--base-w', type=int, default=32)
    ap.add_argument('--tweak', type=int, default=0)
    ap.add_argument('--delta', type=int, default=2)
    ap.add_argument('--degree', type=int, default=3)
    ap.add_argument('--arity', type=int, default=4)
    ap.add_argument('--rounds', type=int, default=2)
    ap.add_argument('--family-seed', type=int, default=42)
    ap.add_argument('--out-len', type=int, default=64)
    ap.add_argument('--verbose', action='store_true',
                    help='Print full numerical trace (for debugging)')
    args = ap.parse_args()

    params = Params(
        base_w=args.base_w,
        tweak=args.tweak,
        delta=args.delta,
        degree=args.degree,
        arity=args.arity,
        rounds=args.rounds,
        family_seed=args.family_seed,
    )

    demo(params, args.out_len, verbose=args.verbose)


if __name__ == '__main__':
    main()