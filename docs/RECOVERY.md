# BTQ wallet recovery

A Bitcoin Quantum wallet in this fork is rooted in **one 32-byte master
secret**, represented as 64 hexadecimal characters. Every receive and change
key is derived from it deterministically (HKDF-SHA512 over network, chain,
and index), so the master secret hex is the single, complete backup.

There are **no seed words** and **no WIF**. The hex is the custody root:

- Losing the master secret loses the funds. The wallet file plus its
  password also contains the secret (encrypted), but treat the hex you
  backed up at creation time as the canonical recovery material.
- Anyone holding the master secret holds the funds. Store it offline; if it
  must live in a file, restrict it to owner-only permissions (`0600`) on a
  volume you control, and never place it in cloud sync or a pasteboard
  manager.

## Recovery procedure

1. **Connect Sparrow to a BTQ Core node** for the wallet's network
   (Settings > Server > Bitcoin Quantum Core). Derivation is network-bound:
   the same master secret produces different keys and addresses on mainnet,
   testnet, signet, and regtest, so recover on the network the funds are on.
2. **Create a new Bitcoin Quantum wallet** (File > New Wallet while
   connected to BTQ Core).
3. **Import the master secret** on the keystore tab: choose the Bitcoin
   Quantum source and paste the 64-character hex. Apply and set a wallet
   password.
4. Addresses re-derive deterministically — receive chain and change chain,
   in order — and are registered with the Core watch wallet. They are
   byte-identical to the original wallet's addresses; verify the first
   receive address against your records before use.
5. **Rescan.** Address registration imports watch descriptors with the
   current timestamp, so history from before the recovery is not visible
   until the node rescans. Run against the watch wallet (default name
   `btq-custody`):

   ```sh
   btq-cli -rpcwallet=btq-custody rescanblockchain 0
   ```

   The node must be fully synced and unpruned for a genesis rescan; if you
   know the wallet's first-use height, rescan from there instead. Reopen or
   refresh the wallet in Sparrow once the rescan completes.

## Notes

- If the original wallet had revealed more addresses than the default gap
  limit, raise the gap limit in the recovered wallet's settings so every
  used address is derived and registered before the rescan.
- The master secret alone is sufficient — no address counters, descriptors,
  or auxiliary state are needed. Unused indices simply never see funds.
- The wallet file encrypts the master secret at rest under the wallet
  password; unlocking the wallet (for example to sign) requires that
  password, but recovery never does — only the hex.
