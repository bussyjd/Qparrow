# Qparrow milestone verification

Verification date: 2026-08-18

## Pinned inputs

- Qparrow implementation commit: `bfbbb393`
- Sparrow starting point: `b99b880c`
- BTQ Core production baseline: `v0.4.4-testnet`, `e2d19e06`
- Exact Bitcoin Core 26.0 ancestor: `44d8b13`
- BTQ test-only follow-up: `5a7edd6b2` updates `feature_p2mr.py` to assert the current P2MR-only Dilithium error; it changes no production code
- Java: Eclipse Temurin 25
- BTQ build: descriptors/SQLite enabled, legacy BDB disabled

## Qparrow and inherited Java surface

Command:

```bash
BTQ_CORE_BIN=/absolute/path/to/btqd ./gradlew test --no-daemon
```

Result:

| Suite | Tests | Skipped | Failures | Errors |
|---|---:|---:|---:|---:|
| Qparrow/Sparrow root | 152 | 0 | 0 | 0 |
| Drongo | 438 | 0 | 0 | 0 |
| Lark | 1 | 0 | 0 | 0 |
| Total | 591 | 0 | 0 | 0 |

The root total includes 26 Qparrow BTQ tests. The real-process test starts `btqd` on regtest and proves descriptor-wallet creation, P2MR address/script binding, quantum-only balance, BTQ PSBT signing/finalization, raw transaction signing, the 2,421-byte ML-DSA signature item, the 1,312-byte public key leaf, rejection after changing a byte inside the ML-DSA signature, successful mempool dry-run, broadcast, mining, and confirmation.

## BTQ Core C++ surface

The selected Dilithium, P2MR, network-policy, wallet, change, descriptor, and PSBT Boost suites ran 139 cases with no errors.

The relevant functional matrix ran 16 scripts. Twelve descriptor/consensus scripts passed. Four legacy-wallet variants were skipped because BDB was not compiled; these paths are not part of Qparrow's descriptor-only custody boundary. The test runner's aggregate result was `ALL ✓ Passed`.

Covered scripts:

```text
feature_dilithium_activation.py
feature_p2mr.py
feature_p2mr_rpc.py
wallet_all_types_simulation.py
wallet_bip360_send_paths.py
wallet_cross_chain_addresses.py
wallet_dilithium_change.py
wallet_dilithium_encrypted_restart_descriptors.py
wallet_dilithium_psbt.py
wallet_dilithium_psbt_multisig.py
wallet_dilithium_send.py
wallet_dilithium_signmessage.py
```

Skipped legacy-BDB variants:

```text
wallet_dilithium_encrypted_restart.py
wallet_dilithium_hd_restore.py
wallet_dilithium_import_restart.py
wallet_dilithium_legacy_spend.py
```

## Artifact gate

`./gradlew jpackageImage` completed successfully. The packaged launcher reports `Qparrow 0.1.0-dev`, opens the BTQ-only desktop, and contains the corrected `com.bitcoinquantum.merged.module` runtime options.

The local macOS distribution is `build/jpackage/Qparrow-0.1.0.zip` (about 90 MB) with SHA-256:

```text
0ff28fcd8bd34e0432f889c93ca59159cdf696f277862f4d4d2503a70eeb3934
```

The zip is an unsigned development artifact. Public releases still require project-owned artwork, release signing/notarization, reproducibility checks, and independent security review.
