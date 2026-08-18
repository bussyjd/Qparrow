# Qparrow node-backed architecture

## Milestone boundary

The first Qparrow milestone proves BTQ's protocol path while BTQ Core retains custody. Qparrow is an intent, validation, and display client; it is not a key store.

```text
User confirmation
      |
      v
Qparrow UI -> typed RPC boundary -> authenticated BTQ Core wallet -> ML-DSA/P2MR consensus
     |                 |                         |
 public profile    opaque tx/PSBT          seed + secret keys
 only              payloads only           never leave node
```

The active launcher is `QparrowDesktop`. It does not initialize Sparrow's `AppServices`, `Storage` wallet databases, Drongo `Wallet`/`PSBT`, Electrum services, or Lark hardware transports. Those inherited sources remain in the tree temporarily so upstream regression tests continue to expose accidental breakage; they are outside the Qparrow runtime boundary.

## Trust decisions

1. `BtqNodeConfig` rejects URI credentials, non-HTTP(S) transports, and plaintext remote HTTP.
2. `BtqCoreWallet.verifyNode` requires a BTQ-identifying subversion and an exact chain match.
3. `ensureWallet` creates/loads a named descriptor wallet with private keys enabled. BTQ Core owns the wallet database and all Dilithium material.
4. `newQuantumAddress` requests type `p2mr`, requires the chain-specific `hrp1z` prefix and exact `OP_2 PUSH32 <merkle-root>` script form, then cross-checks `isdilithium`, `solvable`, and `scriptPubKey` through `getaddressinfo`.
5. `getQuantumBalance` lists only BTQ Core P2MR metadata and requires every returned UTXO to match both its address and script. Ordinary wallet outputs are excluded.
6. `createSpend` rejects non-P2MR destinations before RPC. BTQ Core selects the P2MR input and reports input amount, effective fee, change, and unsigned txid.
7. The UI shows that material before authorization. `signp2mrtransaction` is not called until confirmation.
8. `broadcast` requires `complete=true`, then `testp2mrtransaction.allowed=true`, then a broadcast txid identical to the dry-run txid.
9. PSBTs are transported as opaque strings. Qparrow does not decode or rewrite BTQ input fields.

These checks are fail-closed consistency checks, not remote-node attestation. The authenticated BTQ Core endpoint remains inside the trust boundary and can lie about any RPC result. Qparrow should be used with a locally controlled node for this milestone. Remote HTTPS relies on the operating system trust store and does not yet support certificate pinning.

## Secret handling

`btq-node.properties` contains only URI, network, wallet name, auth mode, timeout, RPC username, and cookie path. It is written atomically with owner-only POSIX permissions where supported. It never contains an RPC password, authorization header, seed, private key, extended key, mnemonic, or PSBT.

Cookie content is read on each RPC call, allowing BTQ Core to rotate it. Basic-auth passwords are copied into an in-memory credential provider and are not serialized. A later hardening milestone should add explicit memory destruction when a session disconnects.

Qparrow currently creates a Core wallet without a wallet passphrase because it does not yet implement a safe unlock/session-expiry flow. Protect the BTQ data directory with host access controls and encrypted storage; wallet encryption support is required before a production release.

## Unsupported paths

Until standalone custody is a separately reviewed milestone, the Qparrow launcher rejects or omits:

- Sparrow `.db` wallet open/import/export;
- BIP39, SLIP39, xprv, seed QR, and descriptor key import;
- Drongo transaction signing and PSBT parsing;
- Lark hardware wallet discovery/signing;
- Electrum/public-server connectivity;
- terminal wallet mode;
- Bitcoin or legacy Dilithium receive destinations;
- non-P2MR send destinations;
- offline/multisigner PSBT editing.

## Testing gates

The unit suite scripts every RPC path and asserts node versus wallet endpoint scoping, parameter order, error mapping, address/script invariants, P2MR-only balances and destinations, incomplete-signature refusal, mempool rejection, txid consistency, opaque PSBT preservation, profile secrecy, and transport validation.

`BtqCoreRegtestIntegrationTest` launches a real `btqd`, mines funds, creates and persists ML-DSA P2MR addresses, signs both raw and PSBT paths, checks the 2,421-byte signature stack item and the leaf script's `PUSHDATA2`-encoded 1,312-byte public key, proves a mutated witness is rejected, broadcasts the valid transaction, mines it, and verifies confirmation.

Every change must also keep the complete inherited Sparrow, Drongo, and Lark test surfaces green until those components are intentionally removed.
