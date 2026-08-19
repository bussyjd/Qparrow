# Qparrow recovery without Qparrow

Qparrow custody is rooted in one 32-byte master secret held in the encrypted
vault (`<network>.qpbtq`). Every receive/change key is derived from it, so the
vault plus its password is the whole backup. This document covers the escape
hatch for recovering funds with **BTQ Core alone**, if Qparrow is ever
unavailable.

BTQ Core cannot re-derive Qparrow's key tree (Qparrow uses an independent
HKDF-SHA512 scheme, not BTQ Core's descriptor derivation). Recovery is therefore
**per address**: Qparrow exports each address's ML-DSA-44 secret key as a BTQ
Core Dilithium WIF, and BTQ Core imports it.

## What Qparrow exports

`BtqCustodyWallet.exportDilithiumWif(chain, index)` returns a Base58Check string
that is exactly what BTQ Core's `importdilithiumkey` expects:

```
Base58Check( secretKeyPrefix ‖ sk(2560) ‖ pk(1312) )
```

`secretKeyPrefix` is `235` on mainnet and `239` on test/signet/regtest
(`base58Prefixes[SECRET_KEY]` in BTQ Core `src/kernel/chainparams.cpp`). The
round trip — export here, `importdilithiumkey` there, identical P2MR address —
is asserted against the real binary in `BtqCoreRegtestIntegrationTest`.

Anyone who holds an exported WIF controls that address's funds. Treat each WIF
as raw key material.

## Recovering funds in BTQ Core

1. Determine how many addresses were used. Qparrow's state file counters bound
   this; if you only have the vault, sweep indices `0..N` on both chains with a
   comfortable margin (a few hundred) — unused indices simply import nothing
   spendable.

2. Export each key (receive chain `0` and change chain `1`) from Qparrow.

3. Create a keyed descriptor wallet in BTQ Core:

   ```sh
   btq-cli -rpcwallet=rescue createwallet "rescue"   # descriptor, private keys enabled
   ```

4. Import every exported WIF:

   ```sh
   btq-cli -rpcwallet=rescue importdilithiumkey "<wif>" "" false
   ```

5. **Rescan explicitly.** `importdilithiumkey`'s third argument is a `rescan`
   flag, but in current BTQ Core it is a no-op (`src/wallet/rpc/dilithium.cpp` —
   `if (fRescan) { /* TODO */ }`), so imported keys with on-chain history show a
   zero balance until you rescan by hand. After importing all keys, run:

   ```sh
   btq-cli -rpcwallet=rescue rescanblockchain 0
   ```

   The node must be fully synced and **unpruned** for a genesis rescan. The
   balance appears once the rescan completes.

6. Spend normally from the rescue wallet (`createp2mrspend` / `signp2mrtransaction`).

## Notes

- This is recovery only; it is never used while Qparrow signs.
- A stale `.qpbackup` restored on its own does not lose funds — the master
  secret derives every index — but Qparrow will not *display* addresses beyond
  its last counter until the counters are advanced. The exhaustive export above
  is independent of the counters and finds everything you actually used.
- Keep the newest `.qpbackup`; back the vault up in several places. It is 179
  bytes and encrypted at rest.
