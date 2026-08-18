# Qparrow

Qparrow is a node-backed desktop wallet for [Bitcoin Quantum](https://bitcoinquantum.com/). It is derived from [Sparrow Wallet](https://github.com/sparrowwallet/sparrow), but its current execution path is intentionally narrow: BTQ Core owns the wallet seed, ML-DSA keys, P2MR metadata, transaction signing, and PSBT finalization.

This repository is an early development milestone. Do not use it with valuable funds without independent review.

## Security boundary

- Qparrow verifies the remote software identity and configured BTQ chain before loading or creating a wallet.
- Receive addresses must be witness-v2 P2MR addresses returned by `getnewdilithiumaddress` and cross-checked with `getaddressinfo`.
- Balances include only UTXOs whose address and script match BTQ Core's persisted P2MR metadata.
- Sends accept only same-network P2MR destinations. The node constructs the transaction, Qparrow displays the exact amount, fee, change, source, destination, and unsigned txid, and BTQ Core signs only after confirmation.
- Broadcast is fail-closed: a complete P2MR witness and successful `testp2mrtransaction` dry run are required first.
- BTQ PSBTs remain opaque base64 in Qparrow so inherited Bitcoin-only parsers cannot drop BTQ fields `0x19`, `0x1a`, or `0x1b`.
- Qparrow stores only public node connection metadata. RPC passwords and wallet secret material are not persisted.
- Inherited Sparrow wallet files, terminal wallet mode, hardware signing, Electrum, Bitcoin key derivation, and offline signing are not reachable from the Qparrow launcher.

See [the Sparrow suitability and license assessment](docs/SPARROW_ASSESSMENT.md), [the architecture and threat boundary](docs/QPARROW_ARCHITECTURE.md), and [the complete wallet reference map](docs/BTQ_WALLET_REFERENCE_MAP.md) before changing wallet code.

## Requirements

- Java 25 or later
- A locally controlled BTQ Core node from [`btq-ag/btq-core`](https://github.com/btq-ag/btq-core)
- Descriptor wallet support in BTQ Core (SQLite)

Clone with submodules:

```bash
git clone --recursive https://github.com/bussyjd/Qparrow.git
cd Qparrow
```

Run all unit and inherited regression tests:

```bash
./gradlew test
```

Run the real BTQ Core regtest integration proof:

```bash
BTQ_CORE_BIN=/absolute/path/to/btq-core/src/btqd ./gradlew test \
  --tests com.sparrowwallet.sparrow.btq.BtqCoreRegtestIntegrationTest
```

Build the desktop package:

```bash
./gradlew jpackage
```

Run from source:

```bash
./qparrow --network regtest
```

The UI defaults to regtest when there is no saved profile. Network choices are mainnet, testnet, signet, and regtest. Plain HTTP RPC is accepted only on a loopback address; remote nodes require HTTPS.

## Authentication

Cookie authentication is the default. Qparrow suggests BTQ Core's standard cookie path for the selected operating system and network. Basic authentication is supported, but its password is memory-only and must be entered after each launch. RPC credentials embedded in a URI are rejected.

## Current non-goals

Standalone Qparrow seed custody, mnemonic import/export, hardware wallet support, and offline signing are deferred until the node-backed P2MR protocol layer has been independently proven. Bitcoin/Sparrow wallet files are not compatible with Qparrow.

## License and attribution

Qparrow is distributed under the Apache License 2.0. It is derived from Sparrow Wallet, Drongo, and Lark, also under Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Qparrow is an independent fork and is not endorsed by the Sparrow Wallet project.
