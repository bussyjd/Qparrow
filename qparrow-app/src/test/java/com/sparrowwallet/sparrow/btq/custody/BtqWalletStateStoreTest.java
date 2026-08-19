// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;

import com.sparrowwallet.sparrow.btq.BtqNodeConfig;
import com.sparrowwallet.sparrow.btq.BtqRpcCredentials;

import static org.junit.jupiter.api.Assertions.*;

class BtqWalletStateStoreTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void persistsReservationBeforeReturningAndKeepsChainsIndependent() throws Exception {
        Path state = temporaryDirectory.resolve("wallet.state");
        byte[] master = master(0);
        BtqWalletStateStore.initializeNew(state, master, BtqNetwork.REGTEST);

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
        BtqWalletStateStore.initializeNew(state, master, BtqNetwork.REGTEST);
        BtqWalletStateStore.reserveNext(state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE);

        assertThrows(IOException.class, () -> BtqWalletStateStore.inspect(state, master(1), BtqNetwork.REGTEST));
        assertThrows(IOException.class, () -> BtqWalletStateStore.inspect(state, master, BtqNetwork.TESTNET));

        byte[] encoded = Files.readAllBytes(state);
        encoded[20] ^= 1;
        Files.write(state, encoded);
        assertThrows(IOException.class, () -> BtqWalletStateStore.inspect(state, master, BtqNetwork.REGTEST));
    }

    @Test
    void missingStateIsFatalAndNeverReissuesIndexZero() throws Exception {
        Path vault = temporaryDirectory.resolve("wallet.qpbtq");
        Path state = temporaryDirectory.resolve("wallet.qpstate");
        char[] password = "correct horse battery staple".toCharArray();
        BtqCustodyWallet.create(vault, state, BtqNetwork.REGTEST, password, new SecureRandom());
        Files.delete(state);
        BtqNodeConfig config = new BtqNodeConfig(URI.create("http://127.0.0.1:18443/"),
                "unused", BtqNetwork.REGTEST, BtqRpcCredentials.none(), Duration.ofSeconds(1));

        assertThrows(IOException.class, () -> BtqCustodyWallet.open(
                vault, state, BtqNetwork.REGTEST, password, config));
        assertFalse(Files.exists(state), "open must not silently recreate lost derivation counters");
    }

    @Test
    void concurrentReservationsSerializeWithoutOverlap() throws Exception {
        Path state = temporaryDirectory.resolve("concurrent.state");
        byte[] master = master(0);
        BtqWalletStateStore.initializeNew(state, master, BtqNetwork.REGTEST);
        try(var executor = Executors.newFixedThreadPool(8)) {
            List<Callable<Integer>> reservations = new ArrayList<>();
            for(int i = 0; i < 64; i++) {
                reservations.add(() -> BtqWalletStateStore.reserveNext(
                        state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE));
            }
            List<Integer> indices = executor.invokeAll(reservations).stream().map(future -> {
                try {
                    return future.get();
                } catch(Exception e) {
                    throw new AssertionError(e);
                }
            }).sorted().toList();
            assertEquals(java.util.stream.IntStream.range(0, 64).boxed().toList(), indices);
        }
        assertEquals(new BtqWalletStateStore.State(64, 0),
                BtqWalletStateStore.inspect(state, master, BtqNetwork.REGTEST));
    }

    private static byte[] master(int delta) {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) master[i] = (byte)(i + delta);
        return master;
    }
}
