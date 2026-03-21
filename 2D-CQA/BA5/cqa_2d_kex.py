#!/usr/bin/env python3
"""cqa_2d_kex.py
Standalone 2D Commutative Quasigroup Action (CQA) BA5 KEX Research Prototype
============================================================================
This is a self-contained Python research prototype for a 2D commutative-action key exchange
built by lifting the scalar 2-adic CQA construction to a 2x2 swap-family
operator action, now using the BA5 balanced-asymmetric coefficient extractor.

Status
------
This is a RESEARCH PROTOTYPE / PoC, not a secure implementation.

Design summary
--------------
1) Keep the public family map over Z/(2^w)Z from the scalar CQA PoC.
2) Use the explicit BA5 5-slot branch schedules on the tuple
   (k1, k2, g1, g2, x).
3) Derive two scalar coefficients
       lambda0(K) = T0_K(u0)
       lambda1(K) = T1_K(u1)
   where T0 and T1 are the two BA5 branch extractors and u0, u1 are
   public branch seeds.
4) Assemble a 2x2 commuting operator
       M_K = lambda0(K) * I + lambda1(K) * S,
   where S = [[0,1],[1,0]].
5) Public key is A_pub = M_A^rounds(G) for a public base vector G=(g1,g2).
6) Shared secret is ss = M_A^rounds(M_B^rounds(G)) = M_B^rounds(M_A^rounds(G)).
7) A transcript-bound session key is derived via HMAC-SHA3-256 HKDF from the
   2D shared secret and the public transcript (A_pub || B_pub).

Why this file is useful
-----------------------
- It is standalone: no external import from cqa_kex_poc.py is required.
- It preserves the current family-generation and scalar machinery.
- It preserves the current swap-family shell and transcript-bound KDF path.
- It implements the explicit BA5 branch schedules analyzed in the paper.
- It provides diagnostics for commutativity, 1D-collapse behavior, the obvious
  one-public-vector recovery condition, and the BA5 public-frame criterion.
- It includes optional branch tracing and a small built-in self-test mode.

IMPORTANT SECURITY WARNING
--------------------------
This construction is only a first research prototype. A 2D linear operator may
still leak its coefficients from one public vector if the chosen base vector G
makes the linear system invertible. The BA5 public-shell Stage-II system also
introduces an additional public-frame determinant Delta_BA5 = u0*u1*(g1^2-g2^2)
that should be monitored. Passing the commutativity check does NOT imply
security.
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
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

# -----------------------------------------------------------------------------
# Core utility helpers (from the scalar CQA PoC)
# -----------------------------------------------------------------------------

def rot_left(xs: List[int], r: int) -> List[int]:
    if not xs:
        return xs
    r %= len(xs)
    return xs[r:] + xs[:r]


def int_to_le_bytes(x: int, length: int) -> bytes:
    return int(x).to_bytes(length, 'little', signed=False)


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

# -----------------------------------------------------------------------------
# Scalar CQA PoC machinery (inlined from cqa_kex_poc.py)
# -----------------------------------------------------------------------------

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

# -----------------------------------------------------------------------------
# 2D BA5 toy parameters
# -----------------------------------------------------------------------------

@dataclass
class Params2DBA5:
    base_w: int
    tweak: int
    delta: int
    degree: int
    arity: int  # must be exactly 5 for the BA5 branch schedules
    rounds: int  # rounds for the vector action (operator application count)
    scalar_rounds: int  # BA5 branch iteration count rho
    family_seed: int
    u0: int
    u1: int
    g1: int
    g2: int

    @property
    def proj_w(self) -> int:
        return self.base_w + self.tweak

    @property
    def MOD(self) -> int:
        return 1 << self.proj_w

    @property
    def pk_len(self) -> int:
        return (self.proj_w + 7) // 8

# -----------------------------------------------------------------------------
# BA5 reduced scalar action T0(x), T1(x)
# -----------------------------------------------------------------------------
#
# We now specialize the current family map to the BA5 balanced-asymmetric
# 5-slot extractor. The public family must have arity 5. The hidden tuple is
# (k1, k2), the public shell coordinates are (g1, g2), and the live scalar
# state x is threaded through two explicit branch schedules:
#
# Branch 0: tuple (k1, k2, g1, g2, x), path P5 -> P4 -> P3 -> P2 -> P1
# Branch 1: tuple (k2, k1, g2, g1, x), path P5 -> P3 -> P4 -> P2 -> P1
#
# This is the direct implementation bridge from the BA5 analytical model.
# -----------------------------------------------------------------------------

def _mul_mod(values: List[int], MOD: int) -> int:
    acc = 1
    for v in values:
        acc = (acc * (v % MOD)) % MOD
    return acc


def _ba5_branch0_round_core(fam: Family, key: List[int], x: int, g1: int, g2: int, trace: bool = False):
    if fam.arity != 5:
        raise ValueError('BA5 branch schedules require family arity == 5')
    if len(key) != 2:
        raise ValueError('BA5 branch schedules require a secret tuple of length 2')

    MOD = fam.MOD
    k1 = key[0] % MOD
    k2 = key[1] % MOD
    gg1 = g1 % MOD
    gg2 = g2 % MOD
    y0 = x % MOD
    P = fam.polys

    y1 = _mul_mod([P[0].eval(k1), P[1].eval(k2), P[2].eval(gg1), P[3].eval(gg2), P[4].eval(y0)], MOD)
    y2 = _mul_mod([P[0].eval(k2), P[1].eval(gg1), P[2].eval(gg2), P[3].eval(y1), P[4].eval(k1)], MOD)
    y3 = _mul_mod([P[0].eval(gg1), P[1].eval(gg2), P[2].eval(y2), P[3].eval(k1), P[4].eval(k2)], MOD)
    y4 = _mul_mod([P[0].eval(gg2), P[1].eval(y3), P[2].eval(k1), P[3].eval(k2), P[4].eval(gg1)], MOD)
    y5 = _mul_mod([P[0].eval(y4), P[1].eval(k1), P[2].eval(k2), P[3].eval(gg1), P[4].eval(gg2)], MOD)

    if not trace:
        return y5

    return y5, {
        'branch': 0,
        'tuple': (k1, k2, gg1, gg2, y0),
        'path': 'P5 -> P4 -> P3 -> P2 -> P1',
        'y0': y0,
        'y1': y1,
        'y2': y2,
        'y3': y3,
        'y4': y4,
        'y5': y5,
    }


def _ba5_branch1_round_core(fam: Family, key: List[int], x: int, g1: int, g2: int, trace: bool = False):
    if fam.arity != 5:
        raise ValueError('BA5 branch schedules require family arity == 5')
    if len(key) != 2:
        raise ValueError('BA5 branch schedules require a secret tuple of length 2')

    MOD = fam.MOD
    # BA5 branch 1 uses (a,b,c,d,e) = (k2,k1,g2,g1,x)
    a = key[1] % MOD
    b = key[0] % MOD
    c = g2 % MOD
    d = g1 % MOD
    y0 = x % MOD
    P = fam.polys

    y1 = _mul_mod([P[0].eval(a), P[1].eval(b), P[2].eval(c), P[3].eval(d), P[4].eval(y0)], MOD)
    y2 = _mul_mod([P[0].eval(b), P[1].eval(c), P[2].eval(y1), P[3].eval(d), P[4].eval(a)], MOD)
    y3 = _mul_mod([P[0].eval(c), P[1].eval(d), P[2].eval(a), P[3].eval(y2), P[4].eval(b)], MOD)
    y4 = _mul_mod([P[0].eval(d), P[1].eval(y3), P[2].eval(a), P[3].eval(b), P[4].eval(c)], MOD)
    y5 = _mul_mod([P[0].eval(y4), P[1].eval(a), P[2].eval(b), P[3].eval(c), P[4].eval(d)], MOD)

    if not trace:
        return y5

    return y5, {
        'branch': 1,
        'tuple': (a, b, c, d, y0),
        'path': 'P5 -> P3 -> P4 -> P2 -> P1',
        'y0': y0,
        'y1': y1,
        'y2': y2,
        'y3': y3,
        'y4': y4,
        'y5': y5,
    }


def ba5_branch0_round(fam: Family, key: List[int], x: int, g1: int, g2: int) -> int:
    """One BA5 branch-0 round."""
    return _ba5_branch0_round_core(fam, key, x, g1, g2, trace=False)


def ba5_branch1_round(fam: Family, key: List[int], x: int, g1: int, g2: int) -> int:
    """One BA5 branch-1 round."""
    return _ba5_branch1_round_core(fam, key, x, g1, g2, trace=False)


def scalar_action_T0_ba5(params2d: Params2DBA5, fam: Family, key: List[int], x: int, trace: bool = False):
    """Iterate the BA5 branch-0 one-round map scalar_rounds times."""
    out = x % fam.MOD
    traces = []
    for r in range(params2d.scalar_rounds):
        if trace:
            out, info = _ba5_branch0_round_core(fam, key, out, params2d.g1, params2d.g2, trace=True)
            info['round_index'] = r + 1
            traces.append(info)
        else:
            out = _ba5_branch0_round_core(fam, key, out, params2d.g1, params2d.g2, trace=False)
    return (out, traces) if trace else out


def scalar_action_T1_ba5(params2d: Params2DBA5, fam: Family, key: List[int], x: int, trace: bool = False):
    """Iterate the BA5 branch-1 one-round map scalar_rounds times."""
    out = x % fam.MOD
    traces = []
    for r in range(params2d.scalar_rounds):
        if trace:
            out, info = _ba5_branch1_round_core(fam, key, out, params2d.g1, params2d.g2, trace=True)
            info['round_index'] = r + 1
            traces.append(info)
        else:
            out = _ba5_branch1_round_core(fam, key, out, params2d.g1, params2d.g2, trace=False)
    return (out, traces) if trace else out

# -----------------------------------------------------------------------------
# Coefficient extraction and commuting 2x2 operator
# -----------------------------------------------------------------------------

def derive_lambdas_ba5(params2d: Params2DBA5, fam: Family, key: List[int], trace: bool = False):
    """
    Derive the two scalar coefficients from the explicit BA5 branch schedules.

    BA5 recipe:
        lambda0(K) = T0_K(u0)
        lambda1(K) = T1_K(u1)
    """
    if trace:
        lam0, trace0 = scalar_action_T0_ba5(params2d, fam, key, params2d.u0, trace=True)
        lam1, trace1 = scalar_action_T1_ba5(params2d, fam, key, params2d.u1, trace=True)
        return lam0, lam1, {'branch0': trace0, 'branch1': trace1}
    lam0 = scalar_action_T0_ba5(params2d, fam, key, params2d.u0, trace=False)
    lam1 = scalar_action_T1_ba5(params2d, fam, key, params2d.u1, trace=False)
    return lam0, lam1


def operator_matrix(lam0: int, lam1: int, MOD: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    M_K = lam0 * I + lam1 * S, with S=[[0,1],[1,0]].
    Explicitly:
        [lam0 lam1]
        [lam1 lam0]
    """
    return ((lam0 % MOD, lam1 % MOD), (lam1 % MOD, lam0 % MOD))


def apply_operator(M: Tuple[Tuple[int, int], Tuple[int, int]], X: Tuple[int, int], MOD: int) -> Tuple[int, int]:
    (a, b), (c, d) = M
    x0, x1 = X
    return ((a * x0 + b * x1) % MOD, (c * x0 + d * x1) % MOD)


def iterate_operator(M: Tuple[Tuple[int, int], Tuple[int, int]], X: Tuple[int, int], rounds: int, MOD: int) -> Tuple[int, int]:
    """Apply M to X exactly `rounds` times.

    BUGFIX context: `rounds` is the vector-action depth and therefore must be
    used consistently both in public-key generation and shared-secret derivation.
    """
    out = X
    for _ in range(rounds):
        out = apply_operator(M, out, MOD)
    return out


def compose_operators(M1, M2, MOD: int):
    (a, b), (c, d) = M1
    (e, f), (g, h) = M2
    return (
        ((a * e + b * g) % MOD, (a * f + b * h) % MOD),
        ((c * e + d * g) % MOD, (c * f + d * h) % MOD),
    )


def operator_power(M, rounds: int, MOD: int):
    """Repeated composition M^rounds for the 2x2 swap-family operator."""
    out = ((1 % MOD, 0), (0, 1 % MOD))
    for _ in range(rounds):
        out = compose_operators(M, out, MOD)
    return out


def v2_mod(x: int, MOD: int) -> int:
    """2-adic valuation clipped at log2(MOD); v2(0) is reported as proj_w."""
    x %= MOD
    if x == 0:
        return MOD.bit_length() - 1
    v = 0
    while (x & 1) == 0:
        x >>= 1
        v += 1
    return v


def swap_eigenvalues(lam0: int, lam1: int, MOD: int) -> Tuple[int, int]:
    """Eigenvalues in the symmetric/antisymmetric basis: mu_+=lam0+lam1, mu_-=lam0-lam1."""
    return ((lam0 + lam1) % MOD, (lam0 - lam1) % MOD)


def degeneracy_report(params2d: Params2DBA5, lam0: int, lam1: int) -> Dict[str, Any]:
    """Diagnose whether the swap design collapses toward a 1D / scalar case.

    For rounds=2 the most relevant checks are:
    - scalar collapse: M^2 becomes alpha*I (off-diagonal term vanishes)
    - one branch zero: one of the two swap-basis channels dies modulo 2^w
    - equal branch powers: mu_+^r == mu_-^r modulo 2^w

    These are not exhaustive security checks, but they directly test the kind of
    'degeneration to 1D' behavior we discussed.
    """
    MOD = params2d.MOD
    mu_plus, mu_minus = swap_eigenvalues(lam0, lam1, MOD)
    M = operator_matrix(lam0, lam1, MOD)
    Mr = operator_power(M, params2d.rounds, MOD)
    mu_plus_r = pow(mu_plus, params2d.rounds, MOD)
    mu_minus_r = pow(mu_minus, params2d.rounds, MOD)
    scalar_collapse = (Mr[0][1] % MOD == 0) and (Mr[1][0] % MOD == 0) and (Mr[0][0] - Mr[1][1]) % MOD == 0
    one_branch_zero = ((mu_plus_r == 0) ^ (mu_minus_r == 0))
    both_branches_zero = (mu_plus_r == 0 and mu_minus_r == 0)
    equal_branch_powers = (mu_plus_r == mu_minus_r)
    return {
        'rounds': params2d.rounds,
        'lam0': lam0 % MOD,
        'lam1': lam1 % MOD,
        'mu_plus': mu_plus,
        'mu_minus': mu_minus,
        'v2_mu_plus': v2_mod(mu_plus, MOD),
        'v2_mu_minus': v2_mod(mu_minus, MOD),
        'mu_plus_to_r': mu_plus_r,
        'mu_minus_to_r': mu_minus_r,
        'M_to_r': Mr,
        'scalar_collapse': scalar_collapse,
        'one_branch_zero': one_branch_zero,
        'both_branches_zero': both_branches_zero,
        'equal_branch_powers': equal_branch_powers,
        'pure_scalar_now': (lam1 % MOD == 0),
        'pure_swap_now': (lam0 % MOD == 0 and lam1 % MOD != 0),
    }

# -----------------------------------------------------------------------------
# 2D key generation, public key generation, shared secret, and KDF
# -----------------------------------------------------------------------------

def keygen_2d_ba5(params2d: Params2DBA5, seed: int) -> List[int]:
    """Reuse the current PoC secret sampling, but output the BA5 hidden tuple (k1, k2)."""
    rng = random.Random(seed)
    s = LegacySampler(base_w=params2d.base_w, proj_w=params2d.proj_w, delta=params2d.delta, rng=rng)
    return [s.structured_odd(), s.structured_odd()]


def public_base_vector(params2d: Params2DBA5) -> Tuple[int, int]:
    return (params2d.g1 % params2d.MOD, params2d.g2 % params2d.MOD)


def pubkey_2d(params2d: Params2DBA5, fam: Family, sk: List[int]) -> Tuple[int, int]:
    """Public key is M_K^rounds(G), not just M_K(G).

    This keeps the postponed rounds>=2 bugfix from the current 2D file.
    """
    lam0, lam1 = derive_lambdas_ba5(params2d, fam, sk)
    M = operator_matrix(lam0, lam1, fam.MOD)
    return iterate_operator(M, public_base_vector(params2d), params2d.rounds, fam.MOD)


def shared_secret_2d(params2d: Params2DBA5, fam: Family, sk: List[int], peer_pk: Tuple[int, int]) -> Tuple[int, int]:
    """Shared secret is M_K^rounds(peer_pk)."""
    lam0, lam1 = derive_lambdas_ba5(params2d, fam, sk)
    M = operator_matrix(lam0, lam1, fam.MOD)
    return iterate_operator(M, peer_pk, params2d.rounds, fam.MOD)


def serialize_elem_2d(params2d: Params2DBA5, x: int) -> bytes:
    return int_to_le_bytes(x, params2d.pk_len)


def serialize_vec2_2d(params2d: Params2DBA5, X: Tuple[int, int]) -> bytes:
    return serialize_elem_2d(params2d, X[0]) + serialize_elem_2d(params2d, X[1])


def kdf_from_shared_2d(params2d: Params2DBA5, ss: Tuple[int, int], context: bytes, out_len: int) -> bytes:
    ss_bytes = serialize_vec2_2d(params2d, ss)
    salt = hashlib.sha3_256(b'CQA-2D-BA5-KEX-salt' + context).digest()
    prk = hkdf_extract(salt, ss_bytes)
    info = b'CQA-2D-BA5-KEX-info' + context
    return hkdf_expand(prk, info, out_len)

# -----------------------------------------------------------------------------
# Diagnostics / attack hooks
# -----------------------------------------------------------------------------

def determinant_G(params2d: Params2DBA5) -> int:
    """Delta = g1^2 - g2^2, relevant for recovering (lam0, lam1) from one public vector."""
    g1, g2 = public_base_vector(params2d)
    return (g1 * g1 - g2 * g2) % params2d.MOD


def determinant_BA5_public_frame(params2d: Params2DBA5) -> int:
    """Delta_BA5 = u0*u1*(g1^2-g2^2), relevant for direct public-shell Stage-II inversion."""
    return (params2d.u0 % params2d.MOD) * (params2d.u1 % params2d.MOD) * determinant_G(params2d) % params2d.MOD


def public_frame_report_BA5(params2d: Params2DBA5) -> Dict[str, Any]:
    """Report the BA5 public-frame quantities used in the v16 design criterion."""
    MOD = params2d.MOD
    g1, g2 = public_base_vector(params2d)
    u0 = params2d.u0 % MOD
    u1 = params2d.u1 % MOD
    D1 = (g1 * u0 + g2 * u1) % MOD
    D2 = (g1 * u1 + g2 * u0) % MOD
    Delta_g = determinant_G(params2d)
    Delta_ba5 = determinant_BA5_public_frame(params2d)
    report = {
        'D1': D1,
        'D2': D2,
        'v2_D1': v2_mod(D1, MOD),
        'v2_D2': v2_mod(D2, MOD),
        'Delta_G': Delta_g,
        'v2_Delta_G': v2_mod(Delta_g, MOD),
        'Delta_BA5': Delta_ba5,
        'v2_Delta_BA5': v2_mod(Delta_ba5, MOD),
        'stage1_full_precision_possible': ((D1 & 1) == 1) or ((D2 & 1) == 1),
        'public_shell_stage2_directly_invertible': ((Delta_ba5 & 1) == 1),
        'direct_one_pub_recovery_invertible': ((Delta_g & 1) == 1),
        'odd_G_policy': ((g1 & 1) == 1) and ((g2 & 1) == 1),
        'u0_parity': (u0 & 1),
        'u1_parity': (u1 & 1),
    }
    report['regime'] = classify_public_frame_BA5(report)
    report['warnings'] = public_frame_warnings_BA5(report)
    return report


def classify_public_frame_BA5(report: Dict[str, Any]) -> str:
    """Classify the current BA5 public frame into a small set of named regimes."""
    if report['direct_one_pub_recovery_invertible']:
        return 'unsafe-direct-shell-recovery'
    if report['public_shell_stage2_directly_invertible']:
        return 'unsafe-public-shell-stage2'
    if report['odd_G_policy'] and report['stage1_full_precision_possible']:
        return 'balanced-ba5'
    if report['odd_G_policy'] and not report['stage1_full_precision_possible']:
        return 'over-hardened-stage1-and-stage2'
    return 'mixed-or-noncanonical'


def public_frame_warnings_BA5(report: Dict[str, Any]) -> List[str]:
    """Convert the BA5 public-frame report into stronger policy messages."""
    warnings: List[str] = []
    regime = report['regime']
    if regime == 'unsafe-direct-shell-recovery':
        warnings.append('WARNING: Delta(G) is invertible, so the obvious one-public-vector 2x2 recovery route is open.')
    if regime == 'unsafe-public-shell-stage2':
        warnings.append('WARNING: Delta_BA5 is invertible, so direct public-shell Stage-II recovery of (S0,S1) is available.')
    if regime == 'balanced-ba5':
        warnings.append('NOTE: balanced BA5 regime detected: odd G blocks direct public-shell Stage-II inversion while Stage I remains fully visible through odd D1/D2.')
    if regime == 'over-hardened-stage1-and-stage2':
        warnings.append('NOTE: over-hardened regime detected: direct public-shell Stage-II inversion is blocked, but Stage I also loses 2-adic precision because both D1 and D2 are even.')
    if not report['odd_G_policy']:
        warnings.append('WARNING: odd-G policy is not satisfied; direct shell-level recovery risk may increase.')
    return warnings


def try_recover_lambdas_from_pub(params2d: Params2DBA5, A_pub: Tuple[int, int]) -> Dict[str, Any]:
    """
    Attempt the obvious 2x2 recovery attack:
        A_pub = M_A * G,
    with
        M_A = [[lam0, lam1],[lam1, lam0]].

    If Delta = g1^2 - g2^2 is invertible, recover lam0 and lam1.
    Otherwise, report that the direct recovery is blocked.
    """
    MOD = params2d.MOD
    g1, g2 = public_base_vector(params2d)
    A1, A2 = A_pub
    Delta = determinant_G(params2d)
    if Delta & 1:
        Delta_inv = pow(Delta, -1, MOD)
        lam0 = ((A1 * g1 - A2 * g2) * Delta_inv) % MOD
        lam1 = ((A2 * g1 - A1 * g2) * Delta_inv) % MOD
        return {
            'recoverable': True,
            'Delta': Delta,
            'lam0': lam0,
            'lam1': lam1,
        }
    return {
        'recoverable': False,
        'Delta': Delta,
        'note': 'Direct 2x2 recovery blocked because Delta is noninvertible modulo 2^w.'
    }


def commutativity_check(params2d: Params2DBA5, fam: Family, A: List[int], B: List[int]) -> bool:
    A_pub = pubkey_2d(params2d, fam, A)
    B_pub = pubkey_2d(params2d, fam, B)
    ssA = shared_secret_2d(params2d, fam, A, B_pub)
    ssB = shared_secret_2d(params2d, fam, B, A_pub)
    return ssA == ssB

# -----------------------------------------------------------------------------
# Small built-in self-test
# -----------------------------------------------------------------------------

def self_test_ba5_defaults(verbose: bool = False) -> Dict[str, Any]:
    """Run a small built-in self-test for the current BA5 implementation."""
    params = Params2DBA5(
        base_w=32,
        tweak=0,
        delta=2,
        degree=3,
        arity=5,
        rounds=2,
        scalar_rounds=1,
        family_seed=12345,
        u0=1,
        u1=2,
        g1=5,
        g2=7,
    )
    fam = setup(Params(
        base_w=params.base_w,
        tweak=params.tweak,
        delta=params.delta,
        degree=params.degree,
        arity=params.arity,
        rounds=1,
        family_seed=params.family_seed,
    ))

    checks: Dict[str, Any] = {}
    checks['arity_is_5'] = (params.arity == 5)

    A = keygen_2d_ba5(params, 111)
    B = keygen_2d_ba5(params, 222)
    checks['secret_len_is_2'] = (len(A) == 2 and len(B) == 2)

    checks['commutativity_default_pair'] = commutativity_check(params, fam, A, B)

    # A few extra random pairs to make regressions easier to catch.
    multi = True
    for sa, sb in [(1, 2), (3, 4), (123, 456), (999, 1001)]:
        if not commutativity_check(params, fam, keygen_2d_ba5(params, sa), keygen_2d_ba5(params, sb)):
            multi = False
            break
    checks['commutativity_multi_pair'] = multi

    frame = public_frame_report_BA5(params)
    checks['balanced_regime_detected'] = (frame['regime'] == 'balanced-ba5')
    checks['direct_one_pub_recovery_blocked'] = (frame['direct_one_pub_recovery_invertible'] is False)
    checks['public_shell_stage2_blocked'] = (frame['public_shell_stage2_directly_invertible'] is False)
    checks['stage1_full_precision_possible'] = (frame['stage1_full_precision_possible'] is True)

    all_ok = all(bool(v) for v in checks.values())
    result = {
        'all_ok': all_ok,
        'checks': checks,
        'frame': frame,
    }
    if verbose:
        print('BA5 self-test report:')
        print(result)
    return result

# -----------------------------------------------------------------------------
# Demo / recipe runner
# -----------------------------------------------------------------------------

def _print_branch_trace(label: str, traces: Dict[str, List[Dict[str, Any]]]) -> None:
    print(f'Branch trace for {label}:')
    for branch_name in ['branch0', 'branch1']:
        print(f'  {branch_name}:')
        for info in traces[branch_name]:
            print(f"    round {info['round_index']}: tuple={info['tuple']}, path={info['path']}")
            print(f"      y0={info['y0']}")
            print(f"      y1={info['y1']}")
            print(f"      y2={info['y2']}")
            print(f"      y3={info['y3']}")
            print(f"      y4={info['y4']}")
            print(f"      y5={info['y5']}")


def demo(params2d: Params2DBA5, seedA: int | None, seedB: int | None, out_len: int, trace_branches: bool = False) -> None:
    p_scalar = Params(
        base_w=params2d.base_w,
        tweak=params2d.tweak,
        delta=params2d.delta,
        degree=params2d.degree,
        arity=params2d.arity,
        rounds=1,
        family_seed=params2d.family_seed,
    )
    fam = setup(p_scalar)

    if seedA is None:
        seedA = int.from_bytes(os.urandom(8), 'little')
    if seedB is None:
        seedB = int.from_bytes(os.urandom(8), 'little')

    A = keygen_2d_ba5(params2d, seedA)
    B = keygen_2d_ba5(params2d, seedB)
    A_pub = pubkey_2d(params2d, fam, A)
    B_pub = pubkey_2d(params2d, fam, B)
    ssA = shared_secret_2d(params2d, fam, A, B_pub)
    ssB = shared_secret_2d(params2d, fam, B, A_pub)

    if trace_branches:
        lam0A, lam1A, traceA = derive_lambdas_ba5(params2d, fam, A, trace=True)
        lam0B, lam1B, traceB = derive_lambdas_ba5(params2d, fam, B, trace=True)
    else:
        lam0A, lam1A = derive_lambdas_ba5(params2d, fam, A)
        lam0B, lam1B = derive_lambdas_ba5(params2d, fam, B)
        traceA = traceB = None

    degA = degeneracy_report(params2d, lam0A, lam1A)
    degB = degeneracy_report(params2d, lam0B, lam1B)
    recA = try_recover_lambdas_from_pub(params2d, A_pub)
    recB = try_recover_lambdas_from_pub(params2d, B_pub)
    frame = public_frame_report_BA5(params2d)

    ctx = serialize_vec2_2d(params2d, A_pub) + serialize_vec2_2d(params2d, B_pub)
    kA = kdf_from_shared_2d(params2d, ssA, ctx, out_len)
    kB = kdf_from_shared_2d(params2d, ssB, ctx, out_len)

    print('2D-CQA BA5 KEX prototype (standalone)')
    print('--------------------------------')
    print(f'base_w={params2d.base_w}, proj_w={params2d.proj_w}, delta={params2d.delta}, degree={params2d.degree}, arity={params2d.arity}')
    print(f'BA5 branch iterations (scalar_rounds)={params2d.scalar_rounds}, vector rounds={params2d.rounds}, family_seed={params2d.family_seed}')
    print(f'u0={params2d.u0}, u1={params2d.u1}')
    print(f'G={public_base_vector(params2d)}')
    print(f'Delta(G)=g1^2-g2^2 mod 2^w = {determinant_G(params2d)}')
    print(f'Delta_BA5=u0*u1*(g1^2-g2^2) mod 2^w = {determinant_BA5_public_frame(params2d)}')
    print(f'public key size = {2 * params2d.pk_len} bytes ({params2d.pk_len} bytes per coordinate)')
    print(f'total KEX transcript size = {4 * params2d.pk_len} bytes (A_pub || B_pub)')
    print()
    print(f'A secret length = {len(A)}')
    print(f'B secret length = {len(B)}')
    print(f'A secret tuple = {A}')
    print(f'B secret tuple = {B}')
    print(f'lambda(A) = ({lam0A}, {lam1A})')
    print(f'lambda(B) = ({lam0B}, {lam1B})')
    print(f'A_pub = {A_pub}')
    print(f'B_pub = {B_pub}')
    print(f'shared secret A = {ssA}')
    print(f'shared secret B = {ssB}')
    print(f'commutativity check = {ssA == ssB}')
    print(f'session key match = {kA == kB}')
    print(f'session key (hex) = {kA.hex()}')
    print()

    if trace_branches:
        _print_branch_trace('A', traceA)
        print()
        _print_branch_trace('B', traceB)
        print()

    print('Degeneracy test (swap design / 1D collapse diagnostics):')
    print(f'degeneracy A = {degA}')
    print(f'degeneracy B = {degB}')
    print()
    print('Direct recovery test from one public vector:')
    print(f'recover A lambdas? {recA}')
    print(f'recover B lambdas? {recB}')
    print()
    print('BA5 public-frame report:')
    print(frame)
    print()

    if frame['warnings']:
        print('BA5 parameter-policy messages:')
        for msg in frame['warnings']:
            print(msg)
        print()

    print('SECURITY WARNING: this is only a research prototype. Passing the')
    print('commutativity check does NOT imply security. In particular, if Delta(G)')
    print('is invertible modulo 2^w, the obvious 2x2 recovery attack may reveal')
    print('(lambda0, lambda1) from one public vector. The BA5 public-frame')
    print('determinant Delta_BA5 should also be monitored.')


def main() -> None:
    ap = argparse.ArgumentParser(description='Standalone 2D CQA BA5 KEX prototype')
    ap.add_argument('--base-w', type=int, default=128)
    ap.add_argument('--tweak', type=int, default=0)
    ap.add_argument('--delta', type=int, default=2)
    ap.add_argument('--degree', type=int, default=3)
    ap.add_argument('--arity', type=int, default=5)
    ap.add_argument('--rounds', type=int, default=2)
    ap.add_argument('--scalar-rounds', type=int, default=1)
    ap.add_argument('--family-seed', type=int, default=12345)
    ap.add_argument('--u0', type=int, default=1)
    ap.add_argument('--u1', type=int, default=2)
    ap.add_argument('--g1', type=int, default=5)
    ap.add_argument('--g2', type=int, default=7)
    ap.add_argument('--seedA', type=int, default=None)
    ap.add_argument('--seedB', type=int, default=None)
    ap.add_argument('--out-len', type=int, default=32)
    ap.add_argument('--trace-branches', action='store_true', help='print the per-round BA5 branch traces y0..y5 for both parties')
    ap.add_argument('--self-test', action='store_true', help='run a small built-in self-test and exit')
    ap.add_argument('--self-test-verbose', action='store_true', help='print the full self-test report when used with --self-test')
    args = ap.parse_args()

    if args.self_test:
        result = self_test_ba5_defaults(verbose=args.self_test_verbose)
        if result['all_ok']:
            print('BA5 self-test passed.')
            if not args.self_test_verbose:
                print(result)
            raise SystemExit(0)
        print('BA5 self-test FAILED.')
        print(result)
        raise SystemExit(1)

    if (args.base_w % 2) != 0:
        raise ValueError('base-w must be even')
    if args.arity != 5:
        raise ValueError('The BA5 proposal requires arity == 5.')
    if args.degree <= 0 or (args.degree % 2) == 0:
        raise ValueError('degree must be positive odd')
    if (args.base_w // 2) - args.delta < 0:
        raise ValueError('delta too large for base-w')

    params2d = Params2DBA5(
        base_w=args.base_w,
        tweak=args.tweak,
        delta=args.delta,
        degree=args.degree,
        arity=args.arity,
        rounds=args.rounds,
        scalar_rounds=args.scalar_rounds,
        family_seed=args.family_seed,
        u0=args.u0,
        u1=args.u1,
        g1=args.g1,
        g2=args.g2,
    )
    demo(params2d, args.seedA, args.seedB, args.out_len, trace_branches=args.trace_branches)


if __name__ == '__main__':
    main()
