# Qparrow

Qparrow is a lean, forward-only Bitcoin Quantum wallet derived from
[Sparrow Wallet](https://github.com/sparrowwallet/sparrow). Qparrow owns the
encrypted master secret, ML-DSA-44 derivation, P2MR construction, transaction
review, and signatures. BTQ Core is a private-key-disabled watch-only backend
for chain data, PSBT construction, policy validation, and broadcast.

This is unreleased development software. Do not use it with valuable funds
without independent cryptographic, application-security, and release review.

## Security boundary

- The only active entry point is `QparrowLauncher` → `QparrowDesktop` →
  `btq.custody`. Inherited Sparrow wallets, Bitcoin signing, Electrum, hardware
  signing, and terminal wallet flows are not initialized.
- Qparrow creates a strict v1 encrypted vault using Argon2id and AES-256-GCM.
  It accepts no Sparrow, BIP32/BIP39, xprv, Core-wallet, or prototype imports.
- Core is verified as BTQ and as the selected network before a descriptor wallet
  is created/loaded with `disable_private_keys=true`, `blank=true`.
- Every receive/change index is authenticated and persisted before display.
  Only the exact public P2MR tree and an `addr()` watch descriptor reach Core.
- Every spend uses explicit user-selected inputs and P2MR-only payments/change.
  Qparrow independently parses the entire PSBT before authorization, displays
  its locally computed fee, reparses before signing, verifies every ML-DSA
  signature locally, and requires default-policy mempool acceptance.
- Qparrow strips witness from Core's returned finalized bytes, computes their
  transaction ID locally, and requires it to equal the signed proposal before
  any policy check or broadcast.
- Encrypted backups contain both the vault and authenticated address counters.
  Restore validates both before installing either and never replaces different
  existing custody files.
- Automatic heap dumps are disabled by the Qparrow build overlay.

See [the architecture](docs/QPARROW_ARCHITECTURE.md),
[wallet reference map](docs/BTQ_WALLET_REFERENCE_MAP.md),
[Sparrow/license assessment](docs/SPARROW_ASSESSMENT.md), and
[verification matrix](docs/VERIFICATION.md).

## Build and test

Requirements are Java 25, the checked-out submodules, and an exact BTQ Core
binary for the real integration gate.

```bash
./gradlew test

BTQ_CORE_BIN=/absolute/path/to/btq-core/src/btqd \
  ./gradlew :test \
  --tests com.sparrowwallet.sparrow.btq.BtqCoreRegtestIntegrationTest

./qparrow --network regtest
./gradlew :qparrow-app:jpackageImage
```

The UI defaults to regtest. Plain HTTP RPC is loopback-only; remote connections
must use HTTPS. Cookie authentication is preferred. Basic-auth passwords and
vault passwords are session-only and are not written to the node profile.

## Custody operations

1. Create a network-specific vault with a password of at least 12 characters.
2. Unlock against a locally controlled BTQ Core node.
3. Reserve a receive address, fund it, and refresh validated P2MR UTXOs.
4. Create an encrypted `.qpbackup` after address use and replace it after each
   new receive/change reservation. Restoring an old counter snapshot can reuse
   addresses, so only the newest backup is safe without a recovery rescan.
   After loss of Core's watch wallet, use **Rebuild Core watch** to register all
   authenticated derivations from genesis and rescan without exposing keys.
5. Select exact inputs, enter a P2MR destination, approve the locally validated
   amount/fee/change, then let Qparrow sign and Core finalize/broadcast.

## License

Qparrow is Apache License 2.0 software derived from Sparrow Wallet, Drongo, and
Lark. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Qparrow is independent and is
not endorsed by the Sparrow Wallet project. This is an engineering assessment,
not legal advice; release counsel should review final branding and notices.
