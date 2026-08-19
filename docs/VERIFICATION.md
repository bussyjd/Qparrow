# Qparrow verification gates

## Automated gates

| Gate | Evidence |
|---|---|
| Strict P2MR address/script codec | `BtqP2mrAddressCodecTest` |
| Network/RPC credential boundary | `BtqNodeConfigTest`, `BtqNodeProfileStoreTest` |
| ML-DSA/P2MR derivation vectors | `BtqCustodyPrimitivesTest` |
| Vault encryption, permissions, tamper, concurrent no-clobber | `BtqSeedVaultTest` |
| Authenticated monotonic receive/change state, missing-state refusal, concurrent locking | `BtqWalletStateStoreTest` |
| Encrypted vault+counter backup/restore and post-unlock vault replacement refusal | `BtqCustodyBackupTest` |
| Strict PSBT review/signing, shuffled outpoints, selected amounts, field allowlist, weight, local witness/txid/wtxid | `BtqPsbtSignerTest` |
| Exact genesis, private-key-disabled wallet, internal change, typed UTXOs, policy/broadcast | `BtqWatchOnlyCoreTest` |
| Exact BTQ Core receive/sign/default-policy/broadcast, node restart, watch-wallet loss and recovery | `BtqCoreRegtestIntegrationTest` |
| Inherited upstream regression signal | root, Drongo, and Lark test suites |

Run:

```bash
./gradlew test

BTQ_CORE_BIN=/absolute/path/to/btq-core/src/btqd \
  ./gradlew :test \
  --tests com.sparrowwallet.sparrow.btq.BtqCoreRegtestIntegrationTest
```

`BtqCoreRegtestIntegrationTest` is **skipped, not failed**, when `BTQ_CORE_BIN`
is unset (`assumeTrue`), so a plain `./gradlew test` is green without ever
touching a node. It is not an automatic gate: the second command above is the
only thing that runs it, and CI must run it explicitly. The binary must be built
from the BTQ Core commit pinned in
[the reference map](BTQ_WALLET_REFERENCE_MAP.md); no tagged release works.

The integration test does not enable `acceptnonstdtxn`; a transaction must pass
BTQ Core's default mempool policy. It proves the independent Java TapSighash,
PSBT fields `0x19`/`0x1a`/`0x1b`, two independently signed inputs, 2,421-byte
signature items, local finalization, mutation rejection, default policy,
broadcast, confirmation, and reopen. Its two-input spend has inputs that Core
shuffles — `walletcreatefundedpsbt` shuffles preset inputs too — but the
resulting order is not asserted; exact shuffled-input resolution is pinned by
`BtqPsbtSignerTest.resolvesShuffledCoreInputsByExactOutpointAndAmount`.
It exercises ordinary restart persistence, explicit unload/load, and recovery
after an unload during an open custody session. It then stops Core, deletes
only the temporary private-key-disabled watch
wallet, restarts Core, reconstructs public P2MR metadata from authenticated
counters without implicit historical scans, performs one genesis rescan, and
rediscovers the outputs.

## Release-only gates

Passing tests establishes an implementable development custody path, not a
production security certification. Public releases additionally require:

- independent review of derivation, FIPS 204 provider use, PSBT parser,
  TapSighash, state/backup formats, and UI authorization boundary;
- reproducible unsigned artifacts followed by platform code signing in a
  separated release workflow, SBOM/dependency review, and provenance;
- Windows/macOS/Linux ACL, swap/crash-dump, clipboard, accessibility, and
  restore-interruption testing;
- a documented stale-backup recovery/rescan procedure before address creation;
- threat testing against a malicious authenticated RPC node and compromised
  desktop, plus a decision on certificate pinning for remote HTTPS;
- hardware-backed/offline signing only as a new versioned design, never a
  compatibility shortcut.
