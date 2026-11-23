# BLINCS manifesto (original strategy note)

*Historical note: the original rationale and strategy note from the repository's owner that set the goals for BLINCS. Preserved here as historical context; for the current normative specification see [`SPEC.md`](../../SPEC.md), and for the current design rationale and quantitative trade-offs see [`DESIGN.md`](../../DESIGN.md).*

## Why hash-based?

* The user already depends on the security of a secure hash function. If the digital signature algorithm additionally relies on other assumptions, then that is an additional thing that can go wrong — the user can be harmed by either a breakthrough against the secure hash function or a breakthrough against the digital signature algorithm. Hash-based digital signatures are strictly more secure than any other digital signature algorithm in the sense that they add strictly fewer assumptions. (HT Daira-Emma Hopwood for teaching me this.)
* Secure hash functions are well-studied, and the historical evidence is that it is feasible to design secure hash functions which withstand attack for at least a few decades. A [survey I did](https://github.com/zooko/hash-function-survey/blob/master/history-of-hash-function-attacks.rst) indicates that no serious secure hash designed since the year 2000 has had its collision resistance broken. The historical track record of second-preimage resistance is even better: no serious secure hash function has ever had its second-preimage resistance broken except for Snefru-2 (the second serious secure hash function ever designed), which was designed in 1990. Every other serious secure hash function ever designed, including MD2 (1989), MD4 (1990), RIPEMD (1990), and MD5 (1992) are still, as far as I know, secure against second-preimage attacks. Hash-based digital signature algorithms rely only upon the second-preimage resistance of a secure hash function. UPDATE: It’s not true in general that hash-based digsigs rely on second-preimage-resistance. JPA’s Gravity-SPHINCS gains some advantages by relying on collision-resistance instead.

## Why *stateless* hash-based?

* Most computer systems today cannot reliably remember mutable state even under non-adversarial conditions. When they fail at that, other mechanisms/layers/users recover from the failure. If you are using a stateful hash-based digital signature, however, and your computer fails in that way, it leaks your secret key. That makes recovery from the failure a more difficult proposition. (See also the science project question below about blockchains.)

## Why a new one?

* SLH-DSA is too inefficient.
* There is now a widely-used, efficient secure hash function that the user may already be relying on – BLAKE3.
* There are now a handful of new techniques that may be able to improve the performance of stateless hash-based digital signatures, starting with “[At the Top of the Hypercube](https://www.iacr.org/cryptodb/data/paper.php?pubkey=35556)”, possibly combined with [SPHINCS+C](https://eprint.iacr.org/2022/778).

## Why BLAKE3?

* BLAKE3 is much more efficient than SHA256 or SHA3.
* BLAKE3 is widely used and increasingly so.
* BLAKE3’s security pedigree goes back to Salsa20, which was published in 2005.
* If a user is relying on both BLAKE3 (for other secure hashing needs) and BLINCS3 (for digital signatures) then there is only one thing that can go wrong (a breakthrough against BLAKE3) that can harm the user.

## Strategy

This strategy is intended to not only produce a secure and useful algorithm, but also to make it widely known and widely used, because only then does it help people, and because independent groups using the same algorithm can produce additional value.

1. A good name: ***BLINCS***
2. Draw on the branding, as well as the actual security, of SPHINCS and BLAKE3.
3. There is only one algorithm – no alternatives, no tuning parameters – because conceptual simplicity helps people understand it and consense upon it. (We saw this with BLAKE2 vs BLAKE3, where the fact that BLAKE2 had multiple variants deterred adoption of BLAKE2 in some cases.) [*]
4. [“The minimax strategy”](https://x.com/zooko/status/1941962247720358186) (HT: Ron Rivest): try to make it perform *well enough* for many use cases, instead of going for the max performance in a few use cases to the detriment of others.
5. Don’t let NIST/NSA anywhere near it. 😂
6. A single “official” implementation with high-quality software engineering: security, performance, portability, good APIs, etc.
7. A simple consistent brand, like “BLINCS3 is the most secure digital signature algorithm which is efficient enough for a lot of use cases.”. That’s a statement which I, personally, would be happy to stand behind due to the three arguments above: “fewer assumptions”, “second-preimage resistance is historically feasible”, and “BLAKE3’s security pedigree”.
8. A team of good cryptographers and engineers who will scrutinize it and maintain the official codebase and put their names on it.
9. A scientific paper for precision and thoroughness, scrutiny, and marketing/communication/branding.
10. 128-bit security. Less would be insufficient for some use cases, more would be overkill.
