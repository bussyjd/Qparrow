# Sparrow suitability assessment for Qparrow

## Decision

Sparrow is a good application scaffold and regression base for a BTQ desktop wallet, but it is not a safe drop-in protocol library for Bitcoin Quantum. Qparrow therefore reuses Sparrow's JavaFX/Gradle application structure while placing a new typed RPC boundary in front of BTQ Core. No inherited Bitcoin wallet, key-derivation, transaction-signing, PSBT-parsing, Electrum, or hardware-wallet path receives BTQ wallet material.

This produces a deliberately asymmetric verdict:

| Area | Suitability | Decision |
|---|---|---|
| Desktop build, JavaFX lifecycle, packaging | Strong | Reuse |
| Mature unit/regression surface | Strong | Keep green as a compatibility tripwire |
| UI patterns and controls | Useful | Reuse selectively |
| Bitcoin wallet domain model | Incorrect for BTQ keys/P2MR | Isolate |
| Drongo transaction and PSBT semantics | Unsafe for BTQ extensions | Do not pass BTQ payloads through it |
| Existing Electrum and hardware flows | Bitcoin-specific | Do not initialize |
| Standalone custody | Technically possible only after new protocol work | Defer to a separately reviewed milestone |

## License result

The repository's [`LICENSE`](../LICENSE) is Apache License 2.0. It permits use, modification, redistribution, and distribution of derivative works, including commercial distribution, subject to its conditions. Qparrow preserves the license, retains upstream copyright headers, marks modified inherited files, and provides [`NOTICE`](../NOTICE) attribution. The new name and independent-project statement avoid implying Sparrow endorsement. Trademarks are not granted by the software license, so Qparrow must continue to use its own name, artwork, release signing identity, package identifiers, and support channels.

The BTQ Core dependency is not copied into this repository or linked into the Qparrow process. It remains a separately running MIT-licensed node reached through JSON-RPC.

This is an engineering assessment, not legal advice; release owners should have counsel review final branding and binary notices before a public production release.

## Modularity result

Sparrow's presentation, wallet model, networking, and signing layers are heavily connected through `AppServices`, Drongo types, events, and controllers. Replacing Bitcoin primitives throughout that graph would create a broad and difficult-to-audit fork. The application entry point is modular enough, however, to launch a separate BTQ-only scene and service layer. Qparrow uses that seam:

```text
Sparrow build/runtime shell
        |
        v
QparrowDesktop -- only active desktop entry point
        |
        v
com.sparrowwallet.sparrow.btq -- typed, fail-closed RPC boundary
        |
        v
BTQ Core descriptor wallet -- seed, ML-DSA keys, P2MR metadata, signing
```

Inherited code remains compiled and tested for now, but it is not initialized by the Qparrow launcher. This is intentional: removing it immediately would erase a large regression signal before the BTQ protocol layer is mature.

## Build path

1. Prove node identity, chain selection, descriptor-wallet lifecycle, P2MR address/script binding, P2MR-only balances, raw signing, mempool dry-run, broadcast, and opaque PSBT transport against real BTQ Core regtest.
2. Keep the inherited Sparrow/Drongo/Lark tests green while replacing only the active runtime seam.
3. Add wallet encryption/session-unlock handling and broader end-user workflows without moving private keys out of BTQ Core.
4. Specify standalone custody independently: ML-DSA key storage, hardened derivation, P2MR metadata persistence, BTQ PSBT fields, backup/recovery, encrypted storage, and hardware interfaces each need new implementations and adversarial tests.
5. Remove unreachable inherited subsystems only after their replacement tests provide equivalent or better coverage.

## Release limitations

This milestone is a protocol proof, not a production custody claim. BTQ Core is fully trusted: its `subversion` string is only an identity sanity check, not cryptographic attestation. A malicious authenticated node can lie about balances, addresses, fees, and transaction construction. Remote connections use system-trusted HTTPS without certificate pinning. Newly created Core wallets do not yet have a Qparrow-managed passphrase/unlock flow. Use a locally controlled node, an encrypted host volume, and non-valuable funds until those gaps are closed and independently reviewed.
