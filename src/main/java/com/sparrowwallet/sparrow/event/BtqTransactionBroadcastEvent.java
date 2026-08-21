package com.sparrowwallet.sparrow.event;

import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.wallet.Wallet;

/**
 * Posted when a Bitcoin Quantum transaction has been accepted into the BTQ Core node's mempool.
 */
public class BtqTransactionBroadcastEvent {
    private final Wallet wallet;
    private final Sha256Hash txId;

    public BtqTransactionBroadcastEvent(Wallet wallet, Sha256Hash txId) {
        this.wallet = wallet;
        this.txId = txId;
    }

    public Wallet getWallet() {
        return wallet;
    }

    public Sha256Hash getTxId() {
        return txId;
    }
}
