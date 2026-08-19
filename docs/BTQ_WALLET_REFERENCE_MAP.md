# BTQ wallet reference map

This map is the mandatory anchor for Qparrow wallet changes. It is based on BTQ
Core `v0.4.4-testnet` production commit `e2d19e06` and exact Bitcoin Core 26.0
ancestor `44d8b13`. The working BTQ branch also contains test-only commit
`5a7edd6b2`. Revalidate this map whenever the Core pin changes.

## Protocol facts that invalidate Bitcoin wallet assumptions

| Boundary | BTQ behavior | Qparrow rule |
|---|---|---|
| Receive | P2MR witness v2, Bech32m, `OP_2 PUSH32 <root>` | Only chain-specific `hrp1z`, exact 34-byte script |
| Key | ML-DSA-44: 32-byte seed, 1312-byte public key, 2560-byte expanded private key | Never use ECKey/BIP32/Drongo keystores |
| Signature | 2420 bytes plus one sighash byte | Bound parsers and fee estimates to the real size |
| Leaf | `<1312-byte key> OP_CHECKSIGDILITHIUM` with `PUSHDATA2` | One v1 policy; no legacy script templates |
| Script limits | BTQ raises relevant element limits to 15000 bytes | Never inherit Bitcoin's 520-byte assumption |
| Derivation | Core Dilithium HD is custom/hardened; Qparrow v1 is a separate network-bound scheme | No compatibility derivation or Core seed import |
| Watch state | P2MR tree metadata is not descriptor-derived | Register exact tree and pair with `addr()` for scanning |
| PSBT | `0x19` leaf, `0x1a` root, `0x1b` ML-DSA script signature | Use only the isolated strict BTQ parser/signer |
| Sighash | BIP341-style `TapSighash`, P2MR script-path extension flag | Single SHA256 component hashes, tagged final hash, `SIGHASH_ALL` only |
| Weight | BTQ `WITNESS_SCALE_FACTOR=16` | Single-key input upper bound 4402; minimum empty input 657 |
| Policy | P2MR-only target despite transitional development networks | Reject every classical input/output path in custody |

## Authoritative BTQ Core production paths

| Concern | Files |
|---|---|
| ML-DSA implementation and sizes | `src/crypto/dilithium_key.{h,cpp}`, `src/crypto/dilithium_pubkey.cpp`, `src/crypto/dilithium_wrapper.{h,c}`, `src/crypto/dilithium/ref/` |
| P2MR leaf policy | `src/script/dilithium_leaf.{h,cpp}`, `src/script/solver.cpp`, `src/script/standard.cpp` |
| P2MR execution and sighash | `src/script/interpreter.{h,cpp}`, `src/script/script.{h,cpp}`, `src/script/sign.{h,cpp}` |
| Consensus/policy/activation | `src/consensus/`, `src/policy/policy.{h,cpp}`, `src/kernel/chainparams.cpp`, `src/validation.cpp` |
| HRPs and chain identity | `src/kernel/chainparams.cpp`, `src/chainparamsbase.cpp` |
| Wallet persistence/key managers | `src/wallet/scriptpubkeyman.{h,cpp}`, `src/wallet/wallet.{h,cpp}`, `src/wallet/walletdb.{h,cpp}` |
| P2MR metadata and signing providers | `src/wallet/p2mr.{h,cpp}` |
| P2MR RPCs | `src/wallet/rpc/p2mr.cpp`, `src/wallet/rpc/dilithium.cpp`, `src/wallet/rpc/wallet.cpp` |
| PSBT wire types | `src/psbt.{h,cpp}`, `src/psbt_dilithium.{h,cpp}` |
| Funding/filling/finalization | `src/wallet/rpc/spend.cpp`, `src/wallet/wallet.cpp`, `src/node/psbt.cpp`, `src/rpc/rawtransaction.cpp` |

## Qparrow custody-to-Core contract

| Flow | Core RPCs | Qparrow owner |
|---|---|---|
| Wallet lifecycle | `listwallets`, `listwalletdir`, `loadwallet`, `createwallet`, `getwalletinfo` | `BtqWatchOnlyCore.ensureWallet` |
| Public registration | `getnewp2mraddress`, `getdescriptorinfo`, `importdescriptors`, `getaddressinfo` | `BtqWatchOnlyCore.registerAddress` |
| UTXOs | `listunspent` | `BtqWatchOnlyCore.listUtxos` validates amount/address/script; Qparrow resolves chain/index |
| Funding | `walletcreatefundedpsbt` with explicit inputs, input weight, quantum change, `add_inputs=false` | `BtqWatchOnlyCore.createFundedPsbt` |
| Signing | no RPC | `BtqPsbtSigner` |
| Final policy gate | `finalizepsbt`, local raw-tx txid binding, `testmempoolaccept` | `BtqWatchOnlyCore.finalizePsbt` |
| Broadcast | `sendrawtransaction` | Exact finalized txid match in `BtqWatchOnlyCore.broadcast` |
| Watch recovery | `getnewp2mraddress`, `importdescriptors` timestamp 0, `rescanblockchain` | Authenticated counters drive public-only reconstruction |

Core is an authenticated public-data and transaction-construction dependency,
not the custody boundary. The local signer treats every PSBT field as hostile.

## Qparrow-owned code surface

| Path | Responsibility |
|---|---|
| `btq/BtqNetwork.java` | Exact chain names, HRPs, RPC defaults |
| `btq/BtqP2mrAddressCodec.java` | Independent Bech32m/P2MR encode, validate, decode |
| `btq/BtqNodeConfig.java`, `BtqRpc*.java` | Authenticated typed RPC transport |
| `btq/custody/BtqCustodySpec.java` | New v1 derivation contract |
| `btq/custody/BtqMldsa44.java` | ML-DSA boundary |
| `btq/custody/BtqP2mrKeyPath.java` | Single-key P2MR commitment |
| `btq/custody/BtqSeedVault.java` | Encrypted seed-at-rest format |
| `btq/custody/BtqWalletStateStore.java` | Authenticated address reservation state |
| `btq/custody/BtqCustodyBackup.java` | Encrypted vault + authenticated counter backup/restore |
| `btq/custody/BtqSpendIntent.java` | User-approved outputs and fee ceiling |
| `btq/custody/BtqPsbtSigner.java` | Strict parser, validation, sighash, signing |
| `btq/custody/BtqWatchOnlyCore.java` | Public-only Core adapter |
| `btq/custody/BtqCustodyWallet.java` | Lean application facade |
| `QparrowLauncher.java`, `QparrowDesktop.java` | Isolated custody-only lifecycle and authorization UI |
| `qparrow-app/` | Minimal distributable module; excludes the Sparrow/Drongo wallet graph |

Any custody change outside these paths must justify crossing the inherited
boundary. Inherited Drongo `Wallet`, `Keystore`, `Transaction`, and `PSBT`
types; Sparrow storage/DAO code; Electrum; Payjoin; hardware-wallet transports;
and Bitcoin import/export screens are prohibited from receiving BTQ secrets or
payloads.

## No-backward-compatibility rule

Custody v1 does not read or reproduce:

- Sparrow wallet databases, keystores, descriptors, BIP39/SLIP39, xprv/xpub;
- BTQ Core private-key wallets or Core Dilithium HD derivation;
- legacy Dilithium addresses or scripts;
- earlier Qparrow node-custody profiles as wallet data;
- classical inputs, recipients, or change;
- Taproot, multisig, Payjoin, or hardware-signing PSBT fields.

Reject unknown versions and unsupported policy. Do not add fallback parsers to
make development artifacts load. If a format is intentionally replaced before
release, increment or replace the format and update its vectors/tests directly.

## Required verification

Qparrow:

```bash
./gradlew :test --tests 'com.sparrowwallet.sparrow.btq.custody.*'
BTQ_CORE_BIN=/absolute/path/to/btqd \
  ./gradlew :test --tests com.sparrowwallet.sparrow.btq.BtqCoreRegtestIntegrationTest
./gradlew test
./gradlew :qparrow-app:jpackageImage
```

BTQ Core wallet/protocol changes should run the directly affected unit and
functional surfaces, including `feature_p2mr*`, `wallet_dilithium_psbt*`,
`wallet_dilithium_change.py`, `wallet_bip360_send_paths.py`, and
`wallet_fundrawtransaction.py`. A failure before the edited case must be
triaged separately rather than treated as proof that the edited case ran.

## Review checklist

Every wallet PR must state:

1. affected layer: consensus, policy, wallet, network, UI, or custody;
2. exact BTQ Core authority and pinned commit;
3. whether input/output script, key, signature, weight, derivation, or PSBT
   assumptions changed;
4. negative tests for node substitution, malformed data, fee/output changes,
   and wrong network/version;
5. whether secrets cross the isolated custody package;
6. upstream Sparrow files touched and why the seam could not remain isolated.
