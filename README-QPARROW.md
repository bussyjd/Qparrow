# Qparrow: Sparrow Wallet with native Bitcoin Quantum support

This fork adds a native Bitcoin Quantum (BTQ) wallet type to
[Sparrow Wallet](https://github.com/sparrowwallet/sparrow). There is no
separate application: Sparrow itself creates, receives on, signs for, and
broadcasts from post-quantum P2MR wallets, served by a BTQ Core node.
Bitcoin behaviour is untouched — every BTQ code path is gated on the new
policy, keystore, and server types, and the full upstream test suites stay
green.

This is unreleased development software. Do not use it with valuable funds
without independent cryptographic, application-security, and release review.

## What a BTQ wallet is

- **Policy `SINGLE_MLDSA`** — one ML-DSA-44 (FIPS 204, "Dilithium2") key per
  address. Public keys are 1312 bytes; signatures are 2420 bytes (a 2421-byte
  witness item with the sighash flag).
- **Script type `P2MR`** (pay-to-merkle-root) — witness version 2,
  `OP_2 <32-byte TapLeaf merkle root>`, encoded as Bech32m: `qbtc1z…` on
  mainnet, `tbtq1z…` on testnet, `qtb1z…` on signet, `qcrt1z…` on regtest.
  The single leaf is `<1312-byte public key> OP_CHECKSIGDILITHIUM` (leaf
  version `0xc0`, one-byte control block `0xc1`).
- **Weight** — BTQ's witness scale factor is 16 (Bitcoin's is 4). A
  single-key P2MR input weighs 4402 WU (~276 vB); virtual size is
  `ceil((stripped_size * 15 + total_size) / 16)`. All fee math runs at
  scale 16.
- **Keystore `SW_BTQ_SEED`** — a single 32-byte master secret. Every key is
  derived from it by HKDF-SHA512 over (network, chain, index): receive
  chain 0, change chain 1. There are no seed words, no BIP32, no xpub, and
  **no public derivation** — deriving any public key requires the master
  secret, so derived public keys are cached and persisted rather than
  recomputed from watch-only material.
- **Sighash** — the BIP341 tapscript sighash with `SIGHASH_ALL`, byte-identical
  to Bitcoin's, so drongo's consensus hashing is reused unchanged.

## Architecture

Three layers, all in this repository:

**drongo submodule — signing engine**
(`drongo/src/main/java/com/sparrowwallet/drongo/btq/`): `Mldsa44` (the FIPS
204 primitive), `BtqDerivation` (HKDF-SHA512, network-bound), `P2MR`
(leaf/root/control-block/address construction), and `BtqPsbtSigner`
(sighash, sign, verify, finalize). PSBTs carry the P2MR data in input fields
`0x19` (leaf script + control block), `0x1a` (merkle root), and `0x1b`
(Dilithium signature). The wallet model — `PolicyType.SINGLE_MLDSA`,
`KeystoreSource.SW_BTQ_SEED`, `ScriptType.P2MR`, `WalletModel.BTQ_CORE` —
lives beside the upstream types as gated branches, and transactions are
constructed locally at scale 16.

**Sparrow node backend**
(`src/main/java/com/sparrowwallet/sparrow/net/btq/`): a BTQ Core node driven
directly over JSON-RPC (`ServerType.BTQ_CORE`) — no Electrum server is
involved. `BtqWatchOnlyCore` maintains a private-key-disabled descriptor
watch wallet inside Core, registers each derived address
(`getnewp2mraddress` plus an `addr()` descriptor import, hard-failing unless
Core returns the byte-identical address, script, and merkle root), reads
history and UTXOs (`BtqCoreHistory`), policy-checks with `testmempoolaccept`,
and broadcasts. Core is a chain-data, policy, and broadcast oracle only — it
never sees key material.

**Gated UI**: while connected to a BTQ Core server, File > New Wallet creates
a `SINGLE_MLDSA`/`P2MR` wallet; the keystore tab offers the Bitcoin Quantum
source (generate a new master secret or import an existing hex); the
Transactions, Receive, Addresses, and UTXOs tabs are reused unchanged; the
Send tab builds, signs (ML-DSA-44), verifies, and broadcasts through the BTQ
path. Bitcoin-only features (hardware wallets, multisig, Electrum, xpub
export) do not apply to BTQ wallets.

## Building and running

Requires Java 25 or higher and the checked-out submodules:

```bash
git clone --recursive <this repository>
cd sparrow
./gradlew :run --args="--network testnet"
```

`./gradlew test` runs the Sparrow suite; `./gradlew :drongo:test` runs the
signing-engine suite (see [docs/VERIFICATION.md](docs/VERIFICATION.md) for
the BTQ-specific gates, including the live regtest integration test).

## Connecting to a BTQ Core node

In Settings > Server, select **Bitcoin Quantum Core**:

- **URL** — the node's RPC host and port (e.g. `127.0.0.1:18332`).
- **Authentication** — *Default* uses the RPC cookie, discovered from the
  **Data Folder** (point it at the node's data directory; the per-network
  subdirectory is found automatically). *User / Pass* uses `rpcuser`/
  `rpcpassword` credentials.
- **Wallet** — the name of the watch-only Core wallet (default
  `btq-custody`). It is created automatically as a descriptor wallet with
  private keys disabled; only public addresses are ever imported into it.

The node must be a BTQ Core build whose `getnewp2mraddress` RPC supports the
`internal` parameter — the connection probes for it and fails closed on
older nodes.

## Creating or importing a wallet

1. Connect to a BTQ Core node (above). File > New Wallet then creates a
   Bitcoin Quantum (`SINGLE_MLDSA`/`P2MR`) wallet.
2. On the keystore tab, choose the Bitcoin Quantum source and either
   **generate** a new 32-byte master secret — it is displayed once as 64 hex
   characters; back it up before continuing — or **import** an existing
   master secret hex.
3. Apply and set a wallet password. The master secret is encrypted at rest
   in the wallet file; receive and change addresses derive deterministically
   and are registered with Core as they are revealed.

The master secret hex is the entire backup. See
[docs/RECOVERY.md](docs/RECOVERY.md) for the custody model and recovery
procedure.

## Status and limitations

**Testnet-proven.** The full native UI flow — create wallet, import master
secret, receive, history from Core, send, sign, broadcast — was completed
end-to-end on the public BTQ testnet on 2026-08-21; the gate transaction
confirmed in block 303704. Evidence and the automated verification gates are
in [docs/VERIFICATION.md](docs/VERIFICATION.md).

Known limitations, tracked as the Phase 6 hardening backlog in the
integration plan document:

- Deriving addresses needs the master secret, so a locked wallet can only
  show addresses already in its derived-pubkey cache. The cache covers the
  look-ahead window, grows on every unlock (including signing), and
  persists — but a wallet that is never unlocked cannot extend it.
- Restoring from a master secret makes BTQ Core back-scan automatically
  (watch descriptors import from the wallet's birth date, or genesis when
  unset); on very large chains the first refresh takes correspondingly
  longer (see [docs/RECOVERY.md](docs/RECOVERY.md)).
- Single key, single leaf, P2MR-only. No watch-only wallets (BTQ has no
  public derivation), no key export, no message signing, no hardware
  signing.

## License

This fork is Apache License 2.0 software derived from Sparrow Wallet,
Drongo, and Lark. See [LICENSE](LICENSE) and [NOTICE](NOTICE). It is
independent and is not endorsed by the Sparrow Wallet project.
