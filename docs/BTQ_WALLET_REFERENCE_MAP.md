# BTQ wallet reference map

This map is the required starting point for Qparrow wallet changes. It is anchored to BTQ Core `v0.4.4-testnet` at `e2d19e06` and its exact Bitcoin Core 26.0 ancestor `44d8b13`. Revalidate the paths and behavior whenever the BTQ Core pin changes.

## Protocol facts that change wallet assumptions

| Boundary | BTQ behavior | Qparrow consequence |
|---|---|---|
| Receive output | P2MR witness v2, Bech32m, `OP_2 PUSH32 <merkle root>` | Require `hrp1z` and a 34-byte scriptPubKey |
| Signing key | ML-DSA-44: 1,312-byte public key, 2,560-byte secret key | Never fit Bitcoin key-size assumptions; node custody only |
| Signature | 2,420 bytes plus one sighash byte in the witness | Validate real witness sizes in integration tests |
| Script element | BTQ raises the relevant element allowance to 15,000 bytes | Do not use Bitcoin's 520-byte parsing/policy assumptions |
| Derivation | BTQ Dilithium HD derivation is custom and hardened-only | Do not derive with Drongo/BIP32 |
| Descriptors | P2MR metadata is wallet-owned and not descriptor-backed | Use `p2mr_id`, `listp2mr`, and `getp2mrinfo` |
| PSBT | Input types `0x19` Dilithium partial sig, `0x1a` leaf script, `0x1b` internal key | Preserve base64 opaquely; BTQ Core processes/finalizes |
| Serialization | Bitcoin transaction serialization is inherited | Raw hex can be relayed opaquely, but not semantically parsed by Drongo |
| Network policy | main/regtest are P2MR-only; the public testnet has transitional legacy behavior | Qparrow enforces P2MR on every network |

## BTQ Core production code

| Concern | Authoritative files |
|---|---|
| ML-DSA implementation, sizes, seed expansion, sign/verify | `src/crypto/dilithium_key.{h,cpp}`, `src/crypto/dilithium_pubkey.cpp`, `src/crypto/dilithium_wrapper.{h,c}`, `src/crypto/dilithium/ref/` |
| P2MR leaf construction and recognition | `src/script/dilithium_leaf.{h,cpp}`, `src/script/solver.cpp`, `src/script/standard.cpp` |
| Witness-v2 execution and Dilithium opcode verification | `src/script/interpreter.{h,cpp}`, `src/script/script.{h,cpp}`, `src/script/sign.{h,cpp}` |
| Consensus/policy limits and activation | `src/consensus/`, `src/policy/policy.{h,cpp}`, `src/kernel/chainparams.cpp`, `src/validation.cpp` |
| Network HRPs and activation regimes | `src/kernel/chainparams.cpp`, `src/chainparamsbase.cpp` |
| Dilithium key encoding/import/export | `src/key_io.{h,cpp}`, `src/outputtype.{h,cpp}`, `src/rpc/output_script.cpp` |
| Wallet key managers and persistence | `src/wallet/scriptpubkeyman.{h,cpp}`, `src/wallet/wallet.{h,cpp}`, `src/wallet/walletdb.{h,cpp}` |
| P2MR metadata, UTXO selection, construction, signing | `src/wallet/p2mr.{h,cpp}` |
| Receive/import/sign-message RPCs | `src/wallet/rpc/dilithium.cpp` |
| P2MR list/info/create/sign/test RPCs | `src/wallet/rpc/p2mr.cpp` |
| RPC registration and wallet scoping | `src/wallet/rpc/wallet.cpp`, `src/wallet/rpc/util.{h,cpp}` |
| PSBT typed fields and serialization | `src/psbt.{h,cpp}`, `src/psbt_dilithium.{h,cpp}` |
| Wallet PSBT filling and finalization | `src/wallet/wallet.cpp`, `src/wallet/rpc/spend.cpp`, `src/node/psbt.cpp`, `src/rpc/rawtransaction.cpp` |
| JSON amount conversion and CLI coercion | `src/rpc/util.cpp`, `src/rpc/client.cpp` |

## Qparrow RPC contract

| Flow | RPCs | Qparrow class |
|---|---|---|
| Identity | `getnetworkinfo`, `getblockchaininfo` | `BtqCoreWallet.verifyNode` |
| Wallet lifecycle | `listwallets`, `listwalletdir`, `loadwallet`, `createwallet`, `getwalletinfo` | `BtqCoreWallet.ensureWallet` |
| Receive | `getnewdilithiumaddress`, `getaddressinfo` | `BtqCoreWallet.newQuantumAddress` |
| Metadata/balance | `listp2mr`, `listunspent` | `listQuantumAddresses`, `getQuantumBalance` |
| Raw spend | `createp2mrspend`, `signp2mrtransaction`, `testp2mrtransaction`, `sendrawtransaction` | `createSpend`, `signSpend`, `dryRun`, `broadcast` |
| PSBT | `walletprocesspsbt`, `combinepsbt`, `finalizepsbt` | `processPsbt`, `combinePsbts`, `finalizePsbt` |
| Node/profile transport | JSON-RPC 2.0 over authenticated HTTP(S) | `BtqNodeConfig`, `BtqRpcCredentials`, `BtqHttpRpcTransport`, `BtqRpcClient`, `BtqNodeProfileStore` |

## Qparrow-owned wallet surface

This is the complete milestone-owned implementation inventory. A change outside these paths must explain why the inherited boundary is being crossed.

| File | Responsibility |
|---|---|
| `src/main/java/com/sparrowwallet/sparrow/QparrowDesktop.java` | Only active desktop scene; connect, receive, P2MR-only balance, review, sign and broadcast intent |
| `btq/BtqNetwork.java` | Exact RPC chain names, HRPs, and default ports |
| `btq/BtqAuthMode.java` | Cookie/basic/none selection |
| `btq/BtqRpcCredentials.java` | Per-request cookie reload and memory-only basic authentication |
| `btq/BtqNodeConfig.java` | URI, endpoint, loopback-HTTP, wallet-name, network, and timeout validation |
| `btq/BtqNodeProfile.java` | Persistable public connection metadata model |
| `btq/BtqNodeProfileStore.java` | Atomic non-secret profile persistence and permission hardening |
| `btq/BtqRpcTransport.java` | Testable transport seam |
| `btq/BtqHttpRpcTransport.java` | Redirect-free Java HTTP JSON transport |
| `btq/BtqRpcClient.java` | JSON-RPC request IDs, endpoint scoping, result typing, and errors |
| `btq/BtqRpcException.java` | Sanitized method/code failure type |
| `btq/BtqP2mrAddressCodec.java` | Independent Bech32m witness-v2 encode/validation |
| `btq/BtqCoreWallet.java` | Descriptor wallet lifecycle and all allowed BTQ wallet RPC workflows |

The matching tests are all files under `src/test/java/com/sparrowwallet/sparrow/btq/`. `BtqCoreRegtestIntegrationTest` is the authoritative end-to-end proof; the remaining files test individual trust-boundary failures.

## BTQ Core wallet test surface

These tests are directly relevant and should run for wallet/protocol changes:

- `test/functional/feature_p2mr.py`
- `test/functional/feature_p2mr_rpc.py`
- `test/functional/feature_dilithium_activation.py`
- `test/functional/wallet_bip360_send_paths.py`
- `test/functional/wallet_dilithium_send.py`
- `test/functional/wallet_dilithium_change.py`
- `test/functional/wallet_dilithium_psbt.py`
- `test/functional/wallet_dilithium_psbt_multisig.py`
- `test/functional/wallet_dilithium_hd_restore.py`
- `test/functional/wallet_dilithium_import_restart.py`
- `test/functional/wallet_dilithium_encrypted_restart.py`
- `test/functional/wallet_dilithium_encrypted_restart_descriptors.py`
- `test/functional/wallet_dilithium_signmessage.py`
- `test/functional/wallet_cross_chain_addresses.py`
- `test/functional/wallet_all_types_simulation.py`
- `test/functional/wallet_dilithium_legacy_spend.py`
- `src/test/dilithium_*_tests.cpp`
- `src/test/p2mr_*_tests.cpp`
- `src/test/psbt_*_tests.cpp`

## Inherited Sparrow surfaces: keep out of the runtime

The following areas encode classical Bitcoin assumptions. They remain useful as upstream regression tests but must not receive BTQ payloads or secrets:

| Inherited surface | Representative paths | Status in Qparrow milestone |
|---|---|---|
| Wallet model, seed/keystore, coin selection | `drongo/.../wallet/Wallet.java`, `Keystore.java`, `DeterministicSeed.java`, `WalletTransaction.java`, `*UtxoSelector.java` | Not initialized |
| Transaction and witness parsing/signing | `drongo/.../protocol/Transaction*.java`, `TransactionWitness.java`, `TransactionSignature.java` | BTQ raw hex stays opaque |
| PSBT parsing/signing/finalization | `drongo/.../psbt/PSBT*.java`, `FinalizingPSBTWallet.java` | BTQ base64 stays opaque |
| Hardware wallets | `lark/...`, Sparrow device/keystore dialogs | Not initialized |
| Sparrow wallet persistence | `src/main/.../io/Storage.java`, database migrations/DAOs | Used only to locate Qparrow config home; no wallet DB is opened |
| Electrum/history/broadcast | `src/main/.../net/ElectrumServer*.java`, `AppServices.java` | Not initialized |
| Desktop wallet controllers | `AppController.java`, `WalletController.java`, transaction tabs/dialogs | Not launched |
| Terminal wallet | `terminal/SparrowTerminal.java`, `terminal/wallet/` | Launcher rejects `--terminal` |
| Import/export and mnemonics | `keystoreimport/`, `control/*Keystore*`, `control/*WalletImport*` | Not launched |

The audit is regenerated with these searches from the repository root:

```bash
rg -l 'Wallet|Keystore|PSBT|Transaction|Electrum|HardwareWallet|Seed|Mnemonic' src/main/java drongo/src/main/java lark/src/main/java
rg --files src/test drongo/src/test lark/src/test
rg -n 'SparrowDesktop|AppServices|SparrowTerminal|WalletController|ElectrumServer|Device' src/main/java/com/sparrowwallet/sparrow/SparrowWallet.java src/main/java/com/sparrowwallet/sparrow/QparrowDesktop.java
```

The last command must return no inherited runtime initialization from either active launcher class. Mere type names in comments are acceptable; constructor calls, static service access, event registration, wallet file opening, and parser invocation are not.

## Review rule

Any proposal that moves an operation from BTQ Core into Qparrow must identify its affected layer (consensus, policy, wallet, network, UI), cite the authoritative BTQ files above, add negative/adversarial tests, and explain why Bitcoin-sized keys, signatures, script elements, descriptors, derivation, and PSBT behavior do not invalidate the implementation. Standalone key custody is a separate milestone, not an incremental UI feature.
