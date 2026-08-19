// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class BtqWalletStateStoreTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void persistsReservationBeforeReturningAndKeepsChainsIndependent() throws Exception {
        Path state = temporaryDirectory.resolve("wallet.state");
        byte[] master = master(0);

        assertEquals(0, BtqWalletStateStore.reserveNext(
                state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE));
        assertEquals(new BtqWalletStateStore.State(1, 0),
                BtqWalletStateStore.inspect(state, master, BtqNetwork.REGTEST));
        assertEquals(1, BtqWalletStateStore.reserveNext(
                state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE));
        assertEquals(0, BtqWalletStateStore.reserveNext(
                state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.CHANGE));
        assertEquals(new BtqWalletStateStore.State(2, 1),
                BtqWalletStateStore.inspect(state, master, BtqNetwork.REGTEST));
    }

    @Test
    void rejectsWrongWalletNetworkAndTampering() throws Exception {
        Path state = temporaryDirectory.resolve("wallet.state");
        byte[] master = master(0);
        BtqWalletStateStore.reserveNext(state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE);

        assertThrows(IOException.class, () -> BtqWalletStateStore.inspect(state, master(1), BtqNetwork.REGTEST));
        assertThrows(IOException.class, () -> BtqWalletStateStore.inspect(state, master, BtqNetwork.TESTNET));

        byte[] encoded = Files.readAllBytes(state);
        encoded[20] ^= 1;
        Files.write(state, encoded);
        assertThrows(IOException.class, () -> BtqWalletStateStore.inspect(state, master, BtqNetwork.REGTEST));
    }

    private static byte[] master(int delta) {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) master[i] = (byte)(i + delta);
        return master;
    }
}
