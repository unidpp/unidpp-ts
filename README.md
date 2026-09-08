# unidpp-ts

Part of UniDPP (github.com/unidpp).
TypeScript implementation of the international DPP framework.
License: MIT.

## Multi-suite packs and the browser limitation (stated plainly)

The issuer mints Tier-A packs in the sovereign co-signature model: one
pack body, several signature slots — e.g. `ecdsa-p256` for an EU anchor
and `sm2` for a CN anchor on the same carrier (see the Rust verifier,
`unidpp-cli` src/packfile.rs `sign_pack_suites` / `check_slot_in`).

This library verifies what this build can compute, and says so when it
cannot:

- **ECDSA P-256/P-384** verify through WebCrypto where available
  (secure browser context, or a runtime with a `webcrypto` global).
- **SM2 (GM/T 0003) and ML-DSA (FIPS 204)** are framing-only here. The
  slots defer with an explicit reason and the verdict degrades — never
  a faked pass, never a crash, never a hand-rolled SM2 implementation
  in TypeScript. A pure-SM2 pack therefore reads as `degraded` with
  "no anchor/computed suite for sm2-sm3 in this build".
- A slot whose key id is not in the cached anchor set degrades that
  slot (`unknown-key`: the verifier's trust configuration does not
  cover the signer); only a signature that fails under its pinned
  anchor fails the verdict (tampering). This mirrors the CLI's
  `SlotCheck` grading order — `packages/verify/src/slotPolicy.ts` is
  the single home of that policy.

**Sovereign-suite implication.** A verifier anchors itself in a
jurisdiction by which suites it can compute. A CN-anchored deployment
that relies on SM2 is verified on a CN-capable terminal (a build with a
GM/T 0003 binding); the reference browser here is EU-classical. Neither
terminal lies about the other's slots: the browser shows the SM2 slot
as deferred with its reason, and a CN terminal shows the same pack
fully verified. Register additional suites by plugging a `CryptoSlot`
(`packages/verify/src/crypto.ts`) — the policy reads the registry, it
does not hard-code a suite list at call sites.
