"""params.py

Draft parameter profiles for the CQA KEX PoC.

These are *initial conservative* placeholders used in the brainstorm abstract.
They follow the empirical rule-of-thumb observed in toy regimes:
- Rounds=2: eff_bits ~ w/2
- Rounds=4: eff_bits ~ w/2 - 1

All profiles keep: arity=3, degree=3, delta=2 (conservative commutative regime).

License: MIT (see SPDX header below). Keep attribution when redistributing.
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

from dataclasses import dataclass


@dataclass(frozen=True)
class CQAParams:
    name: str
    base_w: int
    tweak: int
    delta: int
    degree: int
    arity: int
    rounds: int

    @property
    def proj_w(self) -> int:
        return self.base_w + self.tweak

    @property
    def pk_bytes(self) -> int:
        return (self.proj_w + 7) // 8

    @property
    def kex_transcript_bytes(self) -> int:
        return 2 * self.pk_bytes


# ---- 128-bit tier ----
TIER128_R2 = CQAParams('tier128_r2', base_w=512, tweak=0, delta=2, degree=3, arity=3, rounds=2)
TIER128_R4 = CQAParams('tier128_r4', base_w=512, tweak=2, delta=2, degree=3, arity=3, rounds=4)

# ---- 192-bit tier ----
TIER192_R2 = CQAParams('tier192_r2', base_w=768, tweak=0, delta=2, degree=3, arity=3, rounds=2)
TIER192_R4 = CQAParams('tier192_r4', base_w=768, tweak=2, delta=2, degree=3, arity=3, rounds=4)

# ---- 256-bit tier ----
TIER256_R2 = CQAParams('tier256_r2', base_w=1024, tweak=0, delta=2, degree=3, arity=3, rounds=2)
TIER256_R4 = CQAParams('tier256_r4', base_w=1024, tweak=2, delta=2, degree=3, arity=3, rounds=4)


ALL = {
    p.name: p
    for p in [
        TIER128_R2, TIER128_R4,
        TIER192_R2, TIER192_R4,
        TIER256_R2, TIER256_R4,
    ]
}
