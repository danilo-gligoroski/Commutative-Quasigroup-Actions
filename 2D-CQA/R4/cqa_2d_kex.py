#!/usr/bin/env python3
"""cqa_2d_kex.py
Standalone 2D Commutative Quasigroup Action (CQA) KEX Proof-of-Concept
======================================================================

This is a self-contained Python PoC for a 2D commutative-action key exchange
built by lifting the scalar 2-adic CQA construction to a 2x2 swap-family
operator action.

Status
------
This is a RESEARCH PROTOTYPE / PoC, not a secure implementation.

Design summary
--------------
1) Keep the public family map over Z/(2^w)Z from the scalar CQA PoC.
2) Reserve one public slot for a tag tau.
3) For each tau in {tau0, tau1}, derive a scalar coefficient
   lambda_tau(K) = T_{K,tau}(x_tau)
   using a reduced scalar action built from the same cyclic wiring idea.
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
- It preserves the current family-generation and scalar macro-step machinery.
- It includes the xseed0/xseed1 perturbation hook used in Campaign 3.
- It provides diagnostics for commutativity, 1D-collapse behavior, and the
  obvious one-public-vector recovery condition.

IMPORTANT SECURITY WARNING
--------------------------
This construction is only a first research prototype. A 2D linear operator may
still leak its coefficients from one public vector if the chosen base vector G
makes the linear system invertible. Passing the commutativity check does NOT
imply security.
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
from typing import List, Tuple, Dict, Any


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
# 2D toy parameters
# -----------------------------------------------------------------------------
@dataclass
class Params2D:
    base_w: int
    tweak: int
    delta: int
    degree: int
    arity: int                 # must be >= 4, so we have m-2 secret slots + 1 live state + 1 tag slot
    rounds: int                # rounds for the vector action (operator application count)
    scalar_rounds: int         # rounds used inside T_{K,tau}(x)
    family_seed: int
    tau0: int
    tau1: int
    xseed0: int
    xseed1: int
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
# Reduced scalar action T_{K,tau}(x)
# -----------------------------------------------------------------------------
#
# We start from the current m-ary family map
# f(x1,...,xm) = prod_i P_i(x_i) mod 2^w.
#
# In the 2D proposal, the full public family still has arity m, but the secret
# vector has length m-2. One slot is used for the live scalar state x, and one
# slot is fixed to a public tag tau. We then reuse the same cyclic wiring idea
# on the reduced list [k1,...,k_{m-2}, x, tau] with exactly one live state slot.
#
# NOTE: This is a design choice. It is the most direct bridge from the current
# scalar PoC to the 2D operator proposal.
# -----------------------------------------------------------------------------
def reduced_macro_step(fam: Family, key: List[int], x: int, tau: int) -> int:
    """
    One reduced scalar macro-step T_{K,tau}(x) using the current cyclic idea.

    Inputs:
        fam : public family of arity m
        key : list of length m-2
        x   : live scalar state
        tau : fixed public tag filling the extra public slot

    Construction choice:
        Start from arguments [k1,...,k_{m-2}, x, tau], then rotate only the
        secret vector and keep tau fixed in the final slot of each micro-step.
        The live state y_{i-1} is inserted into a moving slot among the first
        m-1 positions, analogous to the current scalar PoC.
    """
    m = fam.arity
    MOD = fam.MOD
    assert len(key) == m - 2
    K = [k % MOD for k in key]
    x %= MOD
    tau %= MOD

    # First micro-step: [K, x, tau]
    y_prev = fam.f(K + [x, tau])

    # Later micro-steps: rotate K, keep tau fixed in the last slot,
    # insert y_prev into a moving slot among the first m-1 positions.
    for i in range(2, m + 1):
        shiftK = rot_left(K, (i - 1) % (m - 2))
        pos = (m - 1) - i
        args_prefix = shiftK[:pos] + [y_prev] + shiftK[pos:]
        args = args_prefix + [tau]
        assert len(args) == m
        y_prev = fam.f(args)
    return y_prev


def scalar_action_T(params2d: Params2D, fam: Family, key: List[int], x: int, tau: int) -> int:
    """Iterate reduced_macro_step scalar_rounds times."""
    out = x % fam.MOD
    for _ in range(params2d.scalar_rounds):
        out = reduced_macro_step(fam, key, out, tau)
    return out


# -----------------------------------------------------------------------------
# Coefficient extraction and commuting 2x2 operator
# -----------------------------------------------------------------------------
def derive_lambdas(params2d: Params2D, fam: Family, key: List[int]) -> Tuple[int, int]:
    """
    Derive the two scalar coefficients from two public tags and two public x-seeds.

    Perturbation-sweep recipe:
        lambda0(K) = T_{K,tau0}(xseed0)
        lambda1(K) = T_{K,tau1}(xseed1)

    Setting xseed0 = xseed1 = 1 recovers the previous anchored design.
    """
    lam0 = scalar_action_T(params2d, fam, key, params2d.xseed0, params2d.tau0)
    lam1 = scalar_action_T(params2d, fam, key, params2d.xseed1, params2d.tau1)
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


def degeneracy_report(params2d: Params2D, lam0: int, lam1: int) -> Dict[str, Any]:
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
def keygen_2d(params2d: Params2D, seed: int) -> List[int]:
    """Reuse the current PoC secret sampling, but output length m-2."""
    p_scalar = Params(
        base_w=params2d.base_w,
        tweak=params2d.tweak,
        delta=params2d.delta,
        degree=params2d.degree,
        arity=params2d.arity - 1,
        rounds=1,
        family_seed=params2d.family_seed,
    )
    return keygen(p_scalar, seed)


def public_base_vector(params2d: Params2D) -> Tuple[int, int]:
    return (params2d.g1 % params2d.MOD, params2d.g2 % params2d.MOD)


def pubkey_2d(params2d: Params2D, fam: Family, sk: List[int]) -> Tuple[int, int]:
    """Public key is M_K^rounds(G), not just M_K(G).

    This fixes the postponed rounds>=2 bug: the old implementation used one
    operator application for the public key but `rounds` applications inside the
    shared-secret computation, which broke commutativity for rounds>=2.
    """
    lam0, lam1 = derive_lambdas(params2d, fam, sk)
    M = operator_matrix(lam0, lam1, fam.MOD)
    return iterate_operator(M, public_base_vector(params2d), params2d.rounds, fam.MOD)


def shared_secret_2d(params2d: Params2D, fam: Family, sk: List[int], peer_pk: Tuple[int, int]) -> Tuple[int, int]:
    """Shared secret is M_K^rounds(peer_pk)."""
    lam0, lam1 = derive_lambdas(params2d, fam, sk)
    M = operator_matrix(lam0, lam1, fam.MOD)
    return iterate_operator(M, peer_pk, params2d.rounds, fam.MOD)


def serialize_elem_2d(params2d: Params2D, x: int) -> bytes:
    return int_to_le_bytes(x, params2d.pk_len)


def serialize_vec2_2d(params2d: Params2D, X: Tuple[int, int]) -> bytes:
    return serialize_elem_2d(params2d, X[0]) + serialize_elem_2d(params2d, X[1])


def kdf_from_shared_2d(params2d: Params2D, ss: Tuple[int, int], context: bytes, out_len: int) -> bytes:
    ss_bytes = serialize_vec2_2d(params2d, ss)
    salt = hashlib.sha3_256(b'CQA-2D-KEX-salt' + context).digest()
    prk = hkdf_extract(salt, ss_bytes)
    info = b'CQA-2D-KEX-info' + context
    return hkdf_expand(prk, info, out_len)


# -----------------------------------------------------------------------------
# Diagnostics / attack hooks
# -----------------------------------------------------------------------------
def determinant_G(params2d: Params2D) -> int:
    """Delta = g1^2 - g2^2, relevant for recovering (lam0, lam1) from one public vector."""
    g1, g2 = public_base_vector(params2d)
    return (g1 * g1 - g2 * g2) % params2d.MOD


def try_recover_lambdas_from_pub(params2d: Params2D, A_pub: Tuple[int, int]) -> Dict[str, Any]:
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
    Delta = (g1 * g1 - g2 * g2) % MOD
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
    else:
        return {
            'recoverable': False,
            'Delta': Delta,
            'note': 'Direct 2x2 recovery blocked because Delta is noninvertible modulo 2^w.'
        }


def commutativity_check(params2d: Params2D, fam: Family, A: List[int], B: List[int]) -> bool:
    A_pub = pubkey_2d(params2d, fam, A)
    B_pub = pubkey_2d(params2d, fam, B)
    ssA = shared_secret_2d(params2d, fam, A, B_pub)
    ssB = shared_secret_2d(params2d, fam, B, A_pub)
    return ssA == ssB


# -----------------------------------------------------------------------------
# Demo / recipe runner
# -----------------------------------------------------------------------------
def demo(params2d: Params2D, seedA: int | None, seedB: int | None, out_len: int) -> None:
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

    A = keygen_2d(params2d, seedA)
    B = keygen_2d(params2d, seedB)
    A_pub = pubkey_2d(params2d, fam, A)
    B_pub = pubkey_2d(params2d, fam, B)
    ssA = shared_secret_2d(params2d, fam, A, B_pub)
    ssB = shared_secret_2d(params2d, fam, B, A_pub)
    lam0A, lam1A = derive_lambdas(params2d, fam, A)
    lam0B, lam1B = derive_lambdas(params2d, fam, B)
    degA = degeneracy_report(params2d, lam0A, lam1A)
    degB = degeneracy_report(params2d, lam0B, lam1B)
    recA = try_recover_lambdas_from_pub(params2d, A_pub)
    recB = try_recover_lambdas_from_pub(params2d, B_pub)

    ctx = serialize_vec2_2d(params2d, A_pub) + serialize_vec2_2d(params2d, B_pub)
    kA = kdf_from_shared_2d(params2d, ssA, ctx, out_len)
    kB = kdf_from_shared_2d(params2d, ssB, ctx, out_len)

    print('2D-CQA KEX PoC (standalone)')
    print('---------------------------')
    print(f'base_w={params2d.base_w}, proj_w={params2d.proj_w}, delta={params2d.delta}, degree={params2d.degree}, arity={params2d.arity}')
    print(f'scalar_rounds={params2d.scalar_rounds}, vector rounds={params2d.rounds}, family_seed={params2d.family_seed}')
    print(f'tau0={params2d.tau0}, tau1={params2d.tau1}')
    print(f'xseed0={params2d.xseed0}, xseed1={params2d.xseed1}')
    print(f'G={public_base_vector(params2d)}')
    print(f'Delta(G)=g1^2-g2^2 mod 2^w = {determinant_G(params2d)}')
    print(f'public key size = {2 * params2d.pk_len} bytes ({params2d.pk_len} bytes per coordinate)')
    print(f'total KEX transcript size = {4 * params2d.pk_len} bytes (A_pub || B_pub)')
    print()
    print(f'A secret length = {len(A)}')
    print(f'B secret length = {len(B)}')
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
    print('Degeneracy test (swap design / 1D collapse diagnostics):')
    print(f'degeneracy A = {degA}')
    print(f'degeneracy B = {degB}')
    print()
    print('Direct recovery test from one public vector:')
    print(f'recover A lambdas? {recA}')
    print(f'recover B lambdas? {recB}')
    print()
    print('SECURITY WARNING: this is only a research prototype. Passing the')
    print('commutativity check does NOT imply security. In particular, if Delta(G)')
    print('is invertible modulo 2^w, the obvious 2x2 recovery attack may reveal')
    print('(lambda0, lambda1) from one public vector.')


def main() -> None:
    ap = argparse.ArgumentParser(description='Standalone 2D CQA KEX PoC')
    ap.add_argument('--base-w', type=int, default=128)
    ap.add_argument('--tweak', type=int, default=0)
    ap.add_argument('--delta', type=int, default=2)
    ap.add_argument('--degree', type=int, default=3)
    ap.add_argument('--arity', type=int, default=4)
    ap.add_argument('--rounds', type=int, default=2)
    ap.add_argument('--scalar-rounds', type=int, default=1)
    ap.add_argument('--family-seed', type=int, default=12345)
    ap.add_argument('--tau0', type=int, default=1)
    ap.add_argument('--tau1', type=int, default=3)
    ap.add_argument('--xseed0', type=int, default=1)
    ap.add_argument('--xseed1', type=int, default=1)
    ap.add_argument('--g1', type=int, default=5)
    ap.add_argument('--g2', type=int, default=7)
    ap.add_argument('--seedA', type=int, default=None)
    ap.add_argument('--seedB', type=int, default=None)
    ap.add_argument('--out-len', type=int, default=32)
    args = ap.parse_args()

    if (args.base_w % 2) != 0:
        raise ValueError('base-w must be even')
    if args.arity < 4:
        raise ValueError('This 2D proposal expects arity >= 4 so that secret length is m-2 >= 2.')
    if args.degree <= 0 or (args.degree % 2) == 0:
        raise ValueError('degree must be positive odd')
    if (args.base_w // 2) - args.delta < 0:
        raise ValueError('delta too large for base-w')

    params2d = Params2D(
        base_w=args.base_w,
        tweak=args.tweak,
        delta=args.delta,
        degree=args.degree,
        arity=args.arity,
        rounds=args.rounds,
        scalar_rounds=args.scalar_rounds,
        family_seed=args.family_seed,
        tau0=args.tau0,
        tau1=args.tau1,
        xseed0=args.xseed0,
        xseed1=args.xseed1,
        g1=args.g1,
        g2=args.g2,
    )
    demo(params2d, args.seedA, args.seedB, args.out_len)


if __name__ == '__main__':
    main()
