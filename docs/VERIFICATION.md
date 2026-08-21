# Verifying the BTQ integration

Three layers of evidence: the drongo unit suite (golden vectors and
round-trips), a live regtest integration test against a real BTQ Core node,
and the recorded end-to-end testnet gate.

## Unit suite (drongo signing engine)

```bash
./gradlew :drongo:test
```

The BTQ-specific tests and what they pin:

| Area | Tests | Evidence |
|---|---|---|
| Derivation | `btq/BtqDerivationTest` | Byte-exact HKDF-SHA512 golden vectors; network binding; locked derivation returns null rather than throwing (`wallet/BtqLockedDerivationTest`) |
| P2MR construction | `btq/P2MRTest`, `address/P2MRAddressTest`, `protocol/P2MRScriptEqualityTest` | Leaf/TapLeaf-root/control-block/Bech32m vectors from an independent Python reference of the TapLeaf+Bech32m algorithm |
| PSBT fields | `psbt/P2MRPsbtInputTest` | Byte-identical round-trip of input fields `0x19`/`0x1a`/`0x1b` through parse/serialize/combine |
| Signing | `btq/BtqPsbtSignerTest` | Sighash checked byte-for-byte against an independent BIP341 golden vector; 1312-byte leaf script round-trip; full sign → verify → finalize |
| Wallet model | `wallet/BtqKeystoreTest`, `BtqWalletTest`, `BtqWalletSigningTest`, `BtqWalletSendTest`, `BtqKeyCacheTest` | Keystore lifecycle (encrypt/decrypt, cache warm and merge), address/output-script derivation, UI-path `Wallet.sign` dispatch, local scale-16 transaction construction and fee economics |

The full upstream drongo and Sparrow suites must stay green alongside —
every BTQ branch is gated on `SINGLE_MLDSA`/`SW_BTQ_SEED`/`BTQ_CORE`, and
the Bitcoin test surface is the regression check on that gating.

## Live regtest cross-check

```bash
BTQ_CORE_BIN=/absolute/path/to/btq-core/src/btqd \
  ./gradlew :drongo:test --tests com.sparrowwallet.drongo.btq.BtqCoreRegtestIT
```

`BtqCoreRegtestIT` is skipped, not failed, when `BTQ_CORE_BIN` is unset, so
a plain test run never touches a node; CI must run it explicitly. It starts
a private regtest `btqd` (fresh datadir, unique ports), derives a P2MR
address in the JVM, funds it, has Core build a funded PSBT with the explicit
4402 WU input weight, signs and finalizes with `BtqPsbtSigner`, and asserts
`testmempoolaccept` allows the transaction, the locally computed fee matches
Core's, and the transaction confirms. It does not enable `acceptnonstdtxn`:
the spend must pass BTQ Core's default mempool policy.

## Address byte-compatibility with BTQ Core

Every address registration is itself a cross-check, on every wallet, at
runtime: Sparrow derives the address locally from the master secret, hands
Core only the public leaf tree via `getnewp2mraddress`, and hard-fails
unless Core's returned address, `scriptPubKey`, and merkle root are
byte-identical to the local ones (`BtqWatchOnlyCore.registerAddress`). The
subsequent `getaddressinfo` must report the exact script with
`isdilithium=true` and `witness_version=2`. Any divergence between the Java
derivation and Core's P2MR encoding aborts before an address is ever
displayed or funded.

## Testnet gate (2026-08-21)

The full native UI flow was completed end-to-end on the public BTQ testnet:
create wallet → import master secret → balance/history from Core → build
send → finalize → sign (ML-DSA-44 in the Sparrow UI) → broadcast → relayed
peer-to-peer → mined with 2+ confirmations.

Gate transaction
`76e2f14ca68e5dc82e77a0f3f9262379cdfefc82f8b2110b48c6539f7e276dc3`, mined in
block 303704
(`0000000005c786c4398406753e1dcefaab12d9e3e4568ee1d115a5f63a8c2b4e`):

- one P2MR input with the three-item witness (signature, leaf script,
  control block);
- 0.05 tBTQ to a `tbtq1z…` recipient plus 0.04984041 tBTQ change, fee
  15,959 sats;
- weight 5940 WU → virtual size 372 vB at witness scale 16 — the node-side
  math matches drongo's exactly, and the wallet balance moved by precisely
  the fee.

## Scope

Passing these gates establishes a working development custody path, not a
production security certification. A public release additionally requires
independent review of the derivation scheme, the FIPS 204 provider use, the
PSBT and sighash paths, and the UI authorization boundary, plus reproducible
signed artifacts and platform-level secret-handling testing.
