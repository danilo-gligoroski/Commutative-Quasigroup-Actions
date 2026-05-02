# CQA KEX PoC — Commutative Quasigroup Action Key Exchange

**A minimal, self-contained proof-of-concept for Commutative m-ary Quasigroup Actions (CQA) in a 2-adic regime.**

This repository contains a Python implementation of a novel post-quantum key exchange mechanism based on commutative actions of m-ary quasigroups over the ring ℤ/2ʷℤ. The construction is inspired by CSIDH-style class-group actions but uses structured odd-degree polynomials and a cyclic wiring instead of isogenies.

## Features

- **General m-ary support** (arity ≥ 3)
- **Explicit 2-adic parity constraints** (g even, secret components odd)
- **Default g = 2** (smallest even positive integer → guarantees good mixing)
- **Full numerical verification** of commutativity
- **Clean and verbose modes**
- **Frozen low bits** (public keys can be compressed to ~½ size in the 2-adic regime)

## Quick Start

```bash
# Recommended parameters (degree 3, arity 4, rounds 2)
python3 cqa_kex_poc_general_k.py --base-w 512 --family-seed 42 --arity 4 --rounds 2

# Higher security / more rounds
python3 cqa_kex_poc_general_k.py --base-w 512 --family-seed 42 --arity 4 --degree 9 --rounds 85
```

## Installation

```bash
git clone https://github.com/danilo-gligoroski/Commutative-Quasigroup-Actions.git
cd Commutative-Quasigroup-Actions
python3 -m venv .venv
source .venv/bin/activate
# No external dependencies required (pure Python 3.8+)
```

## Command Line Options

| Option            | Default | Description |
|-------------------|---------|-------------|
| `--base-w`        | 32      | Bit width of the modulus (public key size) |
| `--tweak`         | 0       | Additional bits added to base_w |
| `--delta`         | 2       | Controls the distribution of coefficients |
| `--degree`        | 3       | Degree of the odd polynomials (must be odd) |
| `--arity`         | 4       | Number of arguments in the quasigroup operation (m ≥ 3) |
| `--rounds`        | 2       | Number of macro-steps (higher = more security, slower) |
| `--family-seed`   | 42      | Seed for deterministic polynomial generation |
| `--verbose`       | false   | Print full numerical trace (for debugging) |

## Example Output (clean mode)

```
CQA KEX PoC
  params: base_w=512, tweak=0 (proj_w=512), delta=2, degree=3, arity=4, rounds=2
  public key bytes: 64  (KEX transcript: 128 bytes + optional KDF context)
  A_pub = 3c7ba9846eeb9e9ee9d17d39f0a1ee9960a0e7a49f5d97fc99f77cbeb385096c0000000000000000000000000000000000000000000000000000000000000002
  B_pub = 893137f9a539fce1f83013d5f4656d189e14e88f9bc670df79ead814088d3ab40000000000000000000000000000000000000000000000000000000000000002
  commutativity check: True
  shared secret (LE hex): 02000000000000000000000000000000000000000000000000000000000000004059a1a19ca2337ef6c9ad1712e52a872932aa8c2c7c0fac174af7f4aa1b4ded
  shared secret (BE hex): ed4d1baaf4f74a17ac0f7c2c8caa3229872ae51217adc9f67e33a29ca1a159400000000000000000000000000000000000000000000000000000000000000002
  session key match: True
  session key (hex): acfc44faf95f011378546aef966b2d5bdda7288f505acc8d3221614cabf337f0

  note 1: in a 2-adic regime, the low bits can be "frozen" (common suffix), so in little-endian those frozen low bits appear at the start of the hex string.
  and we can use that property to compress the public keys to ~1/2 of their size.

  note 2: This is a research project. Not all parameters give always a perfect commutative action.
  Example: try several times to execute the following command:
  python3 cqa_kex_poc_general_k.py --base-w 512 --family-seed 42 --arity 7 --degree 13 --rounds 85
```

## Important Notes

**Note 1 – Frozen bits & compression**  
In the 2-adic regime many low-order bits become “frozen” (identical across many executions). This allows public keys to be compressed to roughly half their nominal size.

**Note 2 – Research project**  
This is an experimental construction. **Not all parameter combinations guarantee perfect commutativity**.  
For example, the following command sometimes returns `commutativity check: False`:

```bash
python3 cqa_kex_poc_general_k.py --base-w 512 --family-seed 42 --arity 7 --degree 13 --rounds 85
```

Always verify commutativity when using new parameter sets.

## Paper

The mathematical foundations are described in:

> Danilo Gligoroski, *Commutative m-ary Quasigroup Actions in a 2-adic Regime: A CSIDH-like Commutative-Action Candidate and a Key Exchange Protocol*, 2026.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Author

**Danilo Gligoroski**  
Norwegian University of Science and Technology (NTNU)  
Email: danilog@ntnu.no

---

*This is a research prototype. Use at your own risk.*
