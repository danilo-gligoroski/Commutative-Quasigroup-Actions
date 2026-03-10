#!/usr/bin/env python3
"""cqa_kex_poc.py

Commutative Quasigroup Action (CQA) KEX Proof-of-Concept (PoC)
=============================================================

This is a small, self-contained Python PoC for a *commutative action* based key exchange
in the spirit of CSIDH-style commutative group actions, but instantiated using a structured
quasigroup/Latin-style action in a 2-adic regime.

Implementation basis (design constraints)
----------------------------------------
The PoC implements the conservative (empirically commutative) regime used in our experiments:

1) Polynomial maps over the 2-adic ring
   We work modulo 2^w (in code: MOD = 2^proj_w) and use odd-degree polynomials P(x) evaluated via Horner.

2) Q_n conditions from Markovski--{S}uni'{c}--Gligoroski (2010)
   We sample coefficients so that the induced polynomial acts as a permutation on the odd residues (units) modulo 2^w.
   We enforce two parity constraints (Prop. 2 and Prop. 9):
     - sum_i a_i is odd
     - sum_{i odd} a_i is odd
   A simple sufficient construction (used here) is: set a1 odd and all other coefficients even.

3) Legacy 2-adic valuation regime controlled by delta
   SHIFTLeft = 2^(base_w/2 - delta)
   Coefficient sampling (mod 2^proj_w):
     even_coeff = 2 * SHIFTLeft * r
     odd_coeff  = 2 * SHIFTLeft * r + 1

4) Cyclic macro-step wiring (arity m >= 3)
   For m=3 (k=(a,b)), one macro-step expands as:
       y1 = f(a,b,x)
       y2 = f(b,y1,a)
       y3 = f(y2,a,b)
   where f is the per-family map (product of polynomial evaluations).

5) KDF and transcript binding
   The raw shared secret is an element mod 2^w and may exhibit a 2-adic frozen suffix.
   We derive session keys via HKDF-style key derivation (HMAC-SHA3-256), binding the transcript context (A_pub || B_pub).

Security note
-------------
This PoC is for research/interoperability only. It provides no authentication and is vulnerable to
man-in-the-middle attacks unless combined with an authentication layer.

License
-------
Released under a permissive open-source license (MIT). You may use/modify/distribute the code
provided you keep attribution to the original author.

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
from typing import List


def rot_left(xs: List[int], r: int) -> List[int]:
    if not xs:
        return xs
    r %= len(xs)
    return xs[r:] + xs[:r]


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
    """Odd-degree polynomial in the conservative 2-adic commutative regime."""
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
            acc = (acc * P.eval(x)) % self.MOD
        return acc


def macro_step(fam: Family, key: List[int], x: int) -> int:
    m = fam.arity
    assert len(key) == m - 1
    MOD = fam.MOD

    K = [k % MOD for k in key]
    x %= MOD

    y_prev = fam.f(K + [x])
    for i in range(2, m + 1):
        shiftK = rot_left(K, (i - 1) % (m - 1))
        pos = m - i
        args = shiftK[:pos] + [y_prev] + shiftK[pos:]
        y_prev = fam.f(args)
    return y_prev


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


def setup(params: Params) -> Family:
    rng = random.Random(params.family_seed)
    s = LegacySampler(base_w=params.base_w, proj_w=params.proj_w, delta=params.delta, rng=rng)
    polys = [sample_poly(s, params.degree) for _ in range(params.arity)]
    g = s.structured_odd()
    return Family(proj_w=params.proj_w, arity=params.arity, polys=polys, g=g)


def keygen(params: Params, seed: int) -> List[int]:
    rng = random.Random(seed)
    s = LegacySampler(base_w=params.base_w, proj_w=params.proj_w, delta=params.delta, rng=rng)
    return [s.structured_odd() for _ in range(params.arity - 1)]


def pubkey(params: Params, fam: Family, sk: List[int]) -> int:
    return act(fam, sk, fam.g, params.rounds)


def shared_secret(params: Params, fam: Family, sk: List[int], peer_pk: int) -> int:
    return act(fam, sk, peer_pk, params.rounds)


def serialize_elem(params: Params, x: int) -> bytes:
    return int_to_le_bytes(x, params.pk_len)


def kdf_from_shared(params: Params, ss: int, context: bytes, out_len: int) -> bytes:
    ss_le = serialize_elem(params, ss)
    salt = hashlib.sha3_256(b'CQA-KEX-salt' + context).digest()
    prk = hkdf_extract(salt, ss_le)
    info = b'CQA-KEX-info' + context
    return hkdf_expand(prk, info, out_len)


def demo(params: Params, out_len: int) -> None:
    fam = setup(params)

    seedA = int.from_bytes(os.urandom(8), 'little')
    seedB = int.from_bytes(os.urandom(8), 'little')
    A = keygen(params, seedA)
    B = keygen(params, seedB)

    Apub = pubkey(params, fam, A)
    Bpub = pubkey(params, fam, B)

    ssA = shared_secret(params, fam, A, Bpub)
    ssB = shared_secret(params, fam, B, Apub)
    ok = (ssA == ssB)

    # Transcript-bound context (optional; recommended)
    ctx = serialize_elem(params, Apub) + serialize_elem(params, Bpub)

    kA = kdf_from_shared(params, ssA, ctx, out_len)
    kB = kdf_from_shared(params, ssB, ctx, out_len)

    ss_le = serialize_elem(params, ssA)
    ss_be = ss_le[::-1]

    print('CQA KEX PoC')
    print(f'  params: base_w={params.base_w}, tweak={params.tweak} (proj_w={params.proj_w}), delta={params.delta}, degree={params.degree}, arity={params.arity}, rounds={params.rounds}')
    print(f'  public key bytes: {params.pk_len}  (KEX transcript: {2*params.pk_len} bytes + optional KDF context)')
    print(f'  commutativity check: {ok}')

    print(f'  shared secret (LE hex): {ss_le.hex()}')
    print(f'  shared secret (BE hex): {ss_be.hex()}')

    print(f'  session key match: {kA == kB}')
    print(f'  session key (hex): {kA.hex()}')

    print()
    print('  note: in a 2-adic regime, the low bits can be “frozen” (common suffix), so in little-endian those frozen low bits appear at the start of the hex string.')



def main() -> None:
    ap = argparse.ArgumentParser(description='CQA KEX PoC v3 (prints explanatory note)')
    ap.add_argument('--base-w', type=int, default=32)
    ap.add_argument('--tweak', type=int, default=0)
    ap.add_argument('--delta', type=int, default=2)
    ap.add_argument('--degree', type=int, default=3)
    ap.add_argument('--arity', type=int, default=3)
    ap.add_argument('--rounds', type=int, default=2)
    ap.add_argument('--family-seed', type=int, default=12345)
    ap.add_argument('--out-len', type=int, default=32)
    args = ap.parse_args()

    if (args.base_w % 2) != 0:
        raise ValueError('base-w must be even')
    if args.arity < 3:
        raise ValueError('arity must be >= 3')
    if args.degree <= 0 or (args.degree % 2) == 0:
        raise ValueError('degree must be positive odd')
    if (args.base_w // 2) - args.delta < 0:
        raise ValueError('delta too large for base-w')

    params = Params(
        base_w=args.base_w,
        tweak=args.tweak,
        delta=args.delta,
        degree=args.degree,
        arity=args.arity,
        rounds=args.rounds,
        family_seed=args.family_seed,
    )

    demo(params, args.out_len)


if __name__ == '__main__':
    main()
