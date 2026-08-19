# Qparrow custody architecture

## Forward-only wallet format

Qparrow v1 accepts no compatibility inputs. Its only derivation is:

```text
32-byte master secret
  → HKDF-Extract HMAC-SHA512(salt="Qparrow/BTQ/Custody/v1", master)
  → HKDF-Expand HMAC-SHA512(PRK,
       "ML-DSA-44/P2MR" || 00 || ASCII(rpc-chain) || chain-byte
       || big-endian uint32(index) || 01)
  → 32-byte ML-DSA-44 seed
  → 1312-byte public key
  → <pubkey> OP_CHECKSIGDILITHIUM leaf
  → P2MR witness-v2 output
```

The only `rpc-chain` strings are `main`, `test`, `signet`, and `regtest`.
The receive chain byte is `0`; the change chain byte is `1`.

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
strict PSBT parser + TapSighash        default-policy oracle
ML-DSA signing + local finalization     broadcast transport
```

Core is verified by BTQ subversion, exact chain, and pinned genesis hash. The
supported signet is additionally bound to BTQ Core's default
`signet_challenge`; custom signet challenges are rejected. The node is then
constrained to a blank descriptor wallet with private keys disabled. The Core
wallet namespace is deterministically bound to the authenticated local wallet
ID. Every local tree is cross-checked
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

The zero-counter state is created with the vault. A missing state file is fatal
and is never interpreted as a new wallet. An index is written before its
address is displayed. Crashes can create gaps but normal operation cannot reuse
an index. State is wallet/network-bound,
owner-only where supported, locked, atomically replaced, and HMAC-authenticated.

The `.qpbackup` format contains the already encrypted vault plus authenticated
counters. Backup uses the exact encrypted vault bytes retained from the
successful unlock and refuses an on-disk replacement. Restore authenticates
both in temporary files before installation, does not overwrite different
files, and is retry-safe after a partial install. Recovery freshly re-verifies
node identity, synchronization, and pruning state before rebuilding the watch
wallet.
An old valid backup is indistinguishable from a rollback: users must keep the
newest backup. Qparrow can rebuild a lost Core watch wallet by registering every
counter-covered derivation with timestamp `now`, then performing one explicit
genesis rescan. A
production release must still add stale-snapshot detection and advance beyond
any derivations created after an old backup before permitting new addresses.

## Authorization and signing invariants

Core receives only explicit selected outpoints, a fresh local P2MR change
address, and the exact 4,402-weight single-key input bound. Before the user sees
the confirmation, Qparrow independently proves:

1. canonical bounded PSBT v0 and transaction v2;
2. shuffled inputs resolve through an exact approved txid/vout map;
3. every witness UTXO amount, script, and P2MR leaf/control/root matches the
   locally selected coin and derivation;
4. no input is finalized or pre-signed and all use `SIGHASH_ALL`;
5. every output is P2MR and exact approved payments are present;
6. at most one positive output is the fresh local change script;
7. cumulative money is in range, the exact fixed witness stays below BTQ's
   400,000-WU standard limit, and the local fee is below the absolute ceiling;
8. global/input fields are on Qparrow's phase-specific allowlist and output
   maps are empty; unsupported Bitcoin/Taproot/proprietary fields are rejected.

Only that local fee is displayed. After approval the immutable PSBT is parsed
again, the computed fee must match the reviewed fee, and each ML-DSA signature
must verify locally before insertion. Qparrow reparses the signed PSBT, verifies
every signature again, and locally serializes the only supported witness:
`[signature, leaf script, control block]`. It computes txid and wtxid from those
exact bytes. Core's default `testmempoolaccept` policy must allow them and return
both matching identifiers before `sendrawtransaction`; Core is not trusted to
select or assemble witness data.

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
locks after ten minutes, serializes custody operations, and closes
displaced/error sessions. The packaged Qparrow app (`qparrow-app/build.gradle`)
runs with `-XX:-HeapDumpOnOutOfMemoryError`; the root Sparrow build enables heap
dumps and also compiles the custody sources, so only the Qparrow app image
carries this hardening. A managed JVM cannot promise locked native memory; swap,
instrumentation, screen capture, provider internals, and OS crash handling
remain release hardening.

## Known limitations (v1)

- Recovery is counter-bound with no gap-limit scan-ahead, so a stale backup
  hides every coin on an index past the restored counters until the counters are
  advanced (`BtqCustodyWallet.recoverWatchState`).
- Stale-state rollback is not detected: nothing compares restored counters
  against the chain, and coins above them make `listUtxos` fail rather than
  degrade (`BtqCustodyWallet`, `BtqWalletStateStore`).
- Backup requires an open session against a synced, unpruned node, because it
  pins the unlock-time vault bytes and re-reads authenticated state
  (`BtqCustodyBackup.write`).
- Argon2id is fixed at 64 MiB, three iterations, one lane by format version v1;
  the parameters cannot be raised without a new vault format
  (`BtqSeedVault`).
- The vault password cannot be changed: there is no rekey path, so the only way
  to change it is a new wallet (`BtqSeedVault`).
- The JVM cannot guarantee secret zeroisation; `Arrays.fill` covers Qparrow's own
  buffers but not JCE/provider copies, `String` password copies, or swap
  (`BtqCustodySpec`, `QparrowDesktop`).

## Upstream quarantine

The Qparrow launcher and UI are additive. Sparrow's launcher/controllers stay
upstream. A minimal `qparrow-app` module packages only Qparrow/BTQ sources and
their direct runtime dependencies; the full Sparrow graph is test-only. BTQ
payloads never enter Drongo's Bitcoin wallet/transaction/PSBT, Electrum, HWI,
or terminal code. The obsolete Core-key custody class and tests are deleted,
so there is no fallback path.
