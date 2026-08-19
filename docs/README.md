## Qparrow Repository Docs

Developer documentation for Qparrow, a forward-only Bitcoin Quantum custody
wallet derived from Sparrow Wallet. Qparrow is an independent fork and is not
endorsed by the Sparrow Wallet project. Upstream Sparrow's own documentation
lives at https://sparrowwallet.com/docs/.

### [Custody architecture](QPARROW_ARCHITECTURE.md)

The v1 derivation, the responsibility split with BTQ Core, the signing, state,
and backup invariants, and the known v1 limitations.

### [BTQ wallet reference map](BTQ_WALLET_REFERENCE_MAP.md)

The mandatory anchor for wallet changes: BTQ protocol facts, the pinned BTQ Core
commit, the custody-to-Core RPC contract, what is out of scope in v1, and the
review checklist.

### [Verification gates](VERIFICATION.md)

Which test class covers which invariant, how to run the real-node gate, and what
a public release still requires.

### [Sparrow suitability and upstream strategy](SPARROW_ASSESSMENT.md)

Why Sparrow is the scaffold, what is quarantined, the license position, and the
upstream update procedure.

### [Reproducible builds](reproducible.md)

Inherited upstream documentation for reproducing **Sparrow** binaries. Qparrow's
own reproducible-build workflow is a release-only gate and does not exist yet.
