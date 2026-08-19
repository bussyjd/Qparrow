# Qparrow custody architecture

## Forward-only wallet format

Qparrow v1 accepts no compatibility inputs. Its only derivation is:

```text
32-byte master secret
  → HKDF-SHA512(network, receive/change, index)
  → 32-byte ML-DSA-44 seed
  → 1312-byte public key
  → <pubkey> OP_CHECKSIGDILITHIUM leaf
  → P2MR witness-v2 output
```

There is no BIP32, BIP39, xprv, ECDSA/Schnorr, Taproot, legacy Dilithium,
descriptor private key, or pre-P2MR branch. A future design gets a new explicit
version, not another parser in the v1 signing path.

## Responsibility split

```text
Qparrow-owned                         BTQ Core-owned
--------------------------------     ------------------------------
encrypted master-secret vault        chain and mempool data
receive/change derivation             watch-only scan/index
authenticated counters          <--> exact public P2MR metadata
coin/outpoint selection               unsigned PSBT serialization
recipient/change/fee approval         fee estimation
strict PSBT parser + TapSighash        finalization/default policy
ML-DSA signing + local verify          broadcast transport
```

Core is verified as BTQ and the selected chain, then constrained to a blank
descriptor wallet with private keys disabled. Every local tree is cross-checked
against Core's returned address, script, and root and paired with an `addr()`
descriptor. Core never receives a seed or signing capability.

## Components

| Component | Responsibility |
|---|---|
| `BtqCustodySpec` | Strict network/chain/index-separated v1 derivation |
| `BtqMldsa44` | ML-DSA-44 key/sign/verify and exact wire sizes |
| `BtqP2mrKeyPath` | Leaf, TapLeaf root, control block, script, address |
| `BtqSeedVault` | Argon2id + AES-256-GCM encrypted master secret |
| `BtqWalletStateStore` | HMAC-authenticated, pre-reserved counters |
| `BtqCustodyBackup` | Encrypted vault + authenticated state container |
| `BtqSpendIntent` | Exact payments/change/absolute fee ceiling |
| `BtqPsbtSigner` | Independent bounded PSBT-v0 review and signing |
| `BtqWatchOnlyCore` | Typed watch-only Core and broadcast boundary |
| `BtqCustodyWallet` | Locked session facade used by the UI |

## Receive and recovery invariants

An index is written before its address is displayed. Crashes can create gaps
but normal operation cannot reuse an index. State is wallet/network-bound,
owner-only where supported, locked, atomically replaced, and HMAC-authenticated.

The `.qpbackup` format contains the already encrypted vault plus authenticated
counters. Restore authenticates both in temporary files before installation,
does not overwrite different files, and is retry-safe after a partial install.
An old valid backup is indistinguishable from a rollback: users must keep the
newest backup. Qparrow can rebuild a lost Core watch wallet by registering every
counter-covered derivation with timestamp zero and rescanning from genesis. A
production release must still add stale-snapshot detection and advance beyond
any derivations created after an old backup before permitting new addresses.

## Authorization and signing invariants

Core receives only explicit selected outpoints, a fresh local P2MR change
address, and the exact 4,402-weight single-key input bound. Before the user sees
the confirmation, Qparrow independently proves:

1. canonical bounded PSBT v0 and transaction v2;
2. every input is the exact approved txid/vout and local derivation;
3. every witness UTXO and P2MR leaf/control/root matches that derivation;
4. no input is finalized or pre-signed and all use `SIGHASH_ALL`;
5. every output is P2MR and exact approved payments are present;
6. at most one positive output is the fresh local change script;
7. locally computed fee is nonnegative and below the absolute ceiling.

Only that local fee is displayed. After approval the immutable PSBT is parsed
again, the computed fee must match the reviewed fee, and each ML-DSA signature
must verify locally before insertion. Core must finalize it and default
`testmempoolaccept` policy must allow it before `sendrawtransaction`. The
returned finalized bytes are parsed locally and stripped of witness; their
double-SHA256 transaction id must equal the id independently computed from the
locally signed proposal before another RPC is made, preventing finalization
substitution even if Core lies in its JSON response.

BTQ PSBT fields are:

| Type | Key | Value |
|---|---|---|
| `0x19` | type + control block | leaf script + leaf version |
| `0x1a` | type | 32-byte P2MR root |
| `0x1b` | type + 1312-byte public key + leaf hash | 2420-byte signature + sighash byte |

## Secret and session handling

Vault v1 fixes Argon2id at 64 MiB, three iterations, one lane, and encrypts with
AES-256-GCM using the complete header as AAD. Creation uses a per-vault lock and
never replaces an existing file. Opening rejects symlinks, broad POSIX
permissions, wrong network/version/length, and authentication failures.

The UI clears password arrays and temporary key buffers where Java permits,
locks after ten minutes, serializes custody operations, closes displaced/error
sessions, and disables automatic heap dumps through `qparrow.gradle`. A managed
JVM cannot promise locked native memory; swap, instrumentation, screen capture,
provider internals, and OS crash handling remain release hardening.

## Upstream quarantine

The Qparrow launcher and UI are additive. Sparrow's launcher/controllers stay
upstream. A minimal `qparrow-app` module packages only Qparrow/BTQ sources and
their direct runtime dependencies; the full Sparrow graph is test-only. BTQ
payloads never enter Drongo's Bitcoin wallet/transaction/PSBT, Electrum, HWI,
or terminal code. The obsolete Core-key custody class and tests are deleted,
so there is no fallback path.
