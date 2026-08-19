# Qparrow verification gates

## Automated gates

| Gate | Evidence |
|---|---|
| Strict P2MR address/script codec | `BtqP2mrAddressCodecTest` |
| Network/RPC credential boundary | `BtqNodeConfigTest`, `BtqNodeProfileStoreTest` |
| ML-DSA/P2MR derivation vectors | `BtqCustodyPrimitivesTest` |
| Vault encryption, permissions, tamper, concurrent no-clobber | `BtqSeedVaultTest` |
| Authenticated monotonic receive/change state | `BtqWalletStateStoreTest` |
| Encrypted vault+counter backup/restore | `BtqCustodyBackupTest` |
| Strict PSBT review/signing, exact intent, fee ceiling | `BtqPsbtSignerTest` |
| BTQ identity, private-key-disabled wallet, typed UTXOs, funding/finalize/broadcast | `BtqWatchOnlyCoreTest` |
| Exact BTQ Core receive/sign/default-policy/broadcast, node restart, watch-wallet loss and recovery | `BtqCoreRegtestIntegrationTest` |
| Inherited upstream regression signal | root, Drongo, and Lark test suites |

Run:

```bash
./gradlew test

BTQ_CORE_BIN=/absolute/path/to/btq-core/src/btqd \
  ./gradlew :test \
  --tests com.sparrowwallet.sparrow.btq.BtqCoreRegtestIntegrationTest
```

The integration test does not enable `acceptnonstdtxn`; a transaction must pass
BTQ Core's default mempool policy. It proves the independent Java TapSighash,
PSBT fields `0x19`/`0x1a`/`0x1b`, a 2,421-byte transaction signature item,
Core finalization, mutation rejection, broadcast, confirmation, and reopen.
It then stops Core, deletes only the temporary private-key-disabled watch
wallet, restarts Core, reconstructs public P2MR metadata from authenticated
counters with timestamp zero, rescans, and rediscovers the outputs.

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
