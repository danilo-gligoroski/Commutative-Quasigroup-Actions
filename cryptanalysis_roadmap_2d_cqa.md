# Cryptanalysis Roadmap for the 2D CQA Design

## Status of this note

This note summarizes the current cryptanalytic research agenda for the standalone 2D Commutative Quasigroup Action (CQA) key-exchange design. It is written against the **actual public interface** of the current system:

\[
P_K = M_K^{\,r}(G) \in R_w^2,
\qquad
M_K = \lambda_0(K) I + \lambda_1(K) S,
\qquad
S = \begin{bmatrix}0 & 1\1 & 0\end{bmatrix}.
\]

The purpose of this note is to separate:

1. what is currently known empirically,
2. what the actual cryptanalytic targets are,
3. which attack families are scientifically plausible,
4. and which claims remain only heuristic or conjectural.

---

## 1. The actual cryptanalytic object

The first principle is that the public key is **not** the hidden operator matrix itself.
In the current standalone design, the published object is the public orbit vector

\[
P_K = M_K^{\,r}(G) \in R_w^2,
\]

where the hidden coefficient pair is extracted from the reduced scalar actions

\[
\lambda_0(K) = T_{K,	au_0}(xseed_0),
\qquad
\lambda_1(K) = T_{K,	au_1}(xseed_1).
\]

Thus a cryptanalytic attack must begin from the visible orbit point and public parameters, not from a hypothetical exposure of all entries of $M_K$ or $M_K^r$.

This distinction is central. Several informal attack sketches become overstated or even invalid if they assume that the attacker sees a public matrix instead of the actual public orbit vector.

---

## 2. The main security questions

The current design gives rise to several distinct cryptanalytic targets. These should not be conflated.

### 2.1 Exact secret-tuple recovery

Recover the original secret tuple $K$ exactly.
This is the strongest recovery goal, but not always the most relevant one from the action-based point of view.

### 2.2 Visible coefficient recovery

Recover the extracted coefficient pair

\[
(\lambda_0(K), \lambda_1(K)).
\]

In some action systems this may already be sufficient to emulate the public action, even if the underlying tuple $K$ is not recovered.

### 2.3 Action-equivalent hidden representation

Recover any hidden object $K'$ such that

\[
\mathcal{A}_{K'}(V) = \mathcal{A}_K(V)
\]

for all relevant public inputs $V$.
This is a more appropriate one-wayness notion for public-action systems than exact tuple recovery.

### 2.4 Shared-secret recovery from two public keys

Given

\[
A_{\mathrm{pub}} = M_A^{\,r}(G),
\qquad
B_{\mathrm{pub}} = M_B^{\,r}(G),
\]

compute

\[
\mathrm{ss} = M_A^{\,r}(B_{\mathrm{pub}}) = M_B^{\,r}(A_{\mathrm{pub}}).
\]

This is not automatically the same as recovering either participant's exact hidden representation.

### 2.5 Distinguishability

Determine whether public keys

\[
P_K = M_K^{\,r}(G)
\]

can be distinguished from random points of $R_w^2$.
This is conceptually different from inversion and is relevant for transcript-level indistinguishability.

---

## 3. Empirical facts that should anchor the roadmap

The present research program should take the following empirical facts as the starting point.

### 3.1 Corrected multi-round semantics

The postponed `rounds >= 2` public-key mismatch has been fixed in the current standalone implementation. Public keys and shared-secret derivation now use the same vector-round semantics.

### 3.2 Odd-$G$ blocks the direct determinant inversion route

The current mainline policy uses odd public coordinates

\[
G = (g_1, g_2) \in (R_w^	imes)^2.
\]

Then

\[
\Delta(G) = g_1^2 - g_2^2
\]

is noninvertible modulo $2^w$, so the obvious direct one-public-vector recovery route is blocked in the current diagnostic model.

### 3.3 Toy-width collapse is real

At $w = 16$, the design exhibits significant collapse phenomena.
Moreover, the old anchor choice

\[
xseed_0 = xseed_1 = 1
\]

is not neutral there: the perturbation sweeps show that the anchor materially changes the distribution of collapse modes.

### 3.4 High-width odd-$G$ regime is currently the strongest empirical branch

The current odd-$G$ regime remains empirically clean in long runs at widths beginning already at $w = 112$ in the tested data, and the randomized-`xseed` perturbation does not appear to destroy this clean branch.

These empirical facts do **not** prove security, but they do tell us where cryptanalytic effort should be concentrated.

---

## 4. Attack families worth studying

The following attack classes are worth keeping on the roadmap, but they should be classified by maturity.

### 4.1 Baseline direct-recovery attacks

These are the first attacks one should always test:
- direct linear inversion from one public vector,
- determinant-based recovery using $\Delta(G)$,
- and direct solving for the visible coefficients when such inversion is possible.

In the current odd-$G$ regime, the direct route is intentionally blocked, so this attack family currently functions mainly as a baseline sanity check.

### 4.2 Brute-force and meet-in-the-middle attacks on the effective image

These attacks are meaningful if the image of the reduced extractor map is shown to be significantly smaller than the ambient ring.
The toy inversion harness belongs in this category.

This attack class is legitimate as an **experimental model**, but should not be overstated as a break unless the low-entropy image assumption is actually demonstrated for the practical-width regime.

### 4.3 Algebraic and 2-adic solving approaches

A natural idea is to rewrite the public orbit equations in the symmetric/antisymmetric basis and try:
- Hensel lifting,
- 2-adic equation solving,
- or other structured polynomial techniques.

This attack family has mathematical merit, but no explicit efficient solver is currently known for the real public-key interface.

### 4.4 Lattice-style / LLL-style approaches

It is reasonable to ask whether the dyadic structure can be converted into a short-vector or small-root problem.
However, the current state of that idea is still preliminary.
A scientifically meaningful lattice attack would require:

1. an explicit lattice basis built from the real orbit equations,
2. a determinant or volume estimate,
3. a clear “shortness” or small-root condition,
4. and a success argument tied to the current public leakage.

At present, no such explicit formulation is known for the real public-key interface.
Therefore, “LLL attack” should currently be treated as a **research direction**, not as an established attack.

### 4.5 Precomputation, collisions, and rainbow-style attacks

These only become relevant if public keys occupy a low-entropy or highly structured subset of $R_w^2$.
That remains an open empirical and theoretical question.
The current strongest high-width evidence points toward non-collapse rather than toward visible image compression.

### 4.6 Shared-secret recovery attacks

These attacks aim to compute the shared secret from two public keys without fully recovering either original secret tuple.
A realistic passive attack of this kind appears to reduce to one of the following:
- action-equivalent recovery for one party,
- joint hidden-coefficient recovery,
- or a future structured attack that exploits hidden algebraic or dyadic relations between the two public orbit equations.

At present, no method is known that is clearly easier than action recovery itself.

### 4.7 Distinguishers

A separate and important line of work is to test whether public keys can be statistically distinguished from random points of $R_w^2$.
This includes:
- valuation-pattern distinguishers,
- channel-balance statistics,
- determinant surrogates,
- and transcript-level distinguishers.

This should be treated as an independent work package, not merely as a side remark under inversion.

---

## 5. Methodological discipline for future attack proposals

Future attack proposals should be filtered through the following checklist.

### 5.1 Does the attack start from the real public object?

The attack must begin from the actual public leakage

\[
P_K \in R_w^2,
\]

not from a public matrix that is not actually exposed by the protocol.

### 5.2 What is the exact target?

Every proposal should state clearly whether it aims to recover:
- the exact tuple $K$,
- the visible coefficient pair,
- an action-equivalent representation,
- a shared secret,
- or only a distinguisher.

### 5.3 Is the proposal a proof, a heuristic, or a research direction?

Cryptanalytic maturity should be labeled honestly.
The following distinctions are useful:
- **implemented attack**,
- **toy-model attack**,
- **conditional heuristic**,
- **open research direction**.

### 5.4 Does the proposal survive the odd-$G$ regime?

The odd-$G$ policy is part of the current mainline design.
If an attack only works when $\Delta(G)$ is invertible, then it is attacking a weaker regime than the currently recommended one.

### 5.5 Does the proposal address the practical-width branch?

A toy-width break at $w = 16$ is scientifically useful, but it is not evidence against the currently strongest high-width branch unless it scales or transfers in a principled way.

---

## 6. Recommended phased research program

### Phase I: precise definitions

Write down formal definitions of:
- exact-key recovery,
- action-equivalent recovery,
- shared-secret recovery,
- public-key distinguishability.

This phase should ensure that future attack discussions all use the same vocabulary.

### Phase II: toy-width falsification track

Use the collapse-prone toy-width regime to test:
- brute-force models,
- algebraic solving heuristics,
- and toy lattice ideas.

The point here is not to claim practical breaks, but to rapidly reject invalid intuitions and isolate real structural vulnerabilities.

### Phase III: high-width validation track

Re-test any surviving attack idea on the empirically clean odd-$G$ branch, especially near the currently important widths around $112$ and $128$.

This is the decisive transition from a toy-model curiosity to a credible cryptanalytic direction.

### Phase IV: explicit lattice/algebraic formulation track

Either produce a real lattice or 2-adic small-root formulation for the public orbit equations, or conclude that present “LLL attack” language is premature.

This phase should insist on explicit mathematical objects, not just analogies.

### Phase V: cryptographic wrapping track

Study:
- shared-secret indistinguishability,
- transcript binding,
- public-key validation,
- and CPA/CCA conversion.

The goal here is to move from “commutative shared-secret scaffold” toward a standard public-key primitive or KEM understanding.

---

## 7. Current strategic assessment

The strongest current empirical evidence supports the following strategic picture:

1. the toy-width regime is fragile and useful mainly for diagnostics,
2. the odd-$G$ high-width branch is currently the most promising implementation regime,
3. the direct one-public-vector recovery route is blocked there,
4. and there is not yet a mathematically explicit attack that breaks the real public-key interface of the current standalone 2D design.

This does **not** prove security.
But it does mean that future cryptanalysis should be more disciplined than “apply LLL somewhere.”
Any serious attack claim should specify the public leakage model, the inversion target, the mathematical mechanism, and the empirical regime in which it is expected to work.

---

## 8. Immediate action items

The next practical steps should be:

1. maintain a separate attack-notebook for toy-width attack experiments;
2. keep the paper language conservative, using “conditional attack family” rather than “attack” unless there is an explicit working formulation;
3. continue testing robustness across family seeds and across widths in the transition band;
4. investigate the symmetric/antisymmetric basis as the most natural coordinate system for future algebraic and potential lattice work;
5. and treat shared-secret recovery and distinguishability as first-class targets, not merely appendices to one-wayness.

---

## 9. Summary

The 2D CQA design should now be cryptanalyzed as a concrete public-orbit action on $R_w^2$.
The correct roadmap is therefore:

- formalize the exact cryptanalytic targets,
- evaluate brute-force, algebraic, distinguishing, and possible lattice ideas as separate attack families,
- distinguish toy-width failures from practical-width evidence,
- and require that every future attack proposal match the actual public interface of the design.

This is the right path toward converting the current empirical understanding of the 2D CQA system into a mature research program.
