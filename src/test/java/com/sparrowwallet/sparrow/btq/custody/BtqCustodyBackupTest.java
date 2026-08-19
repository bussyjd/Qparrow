// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class BtqCustodyBackupTest {
    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

    @TempDir
    Path temporaryDirectory;

    @Test
    void authenticatedBackupRestoresBothCustodyFilesAndIsRetrySafe() throws Exception {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) master[i] = (byte)(0x40 + i);
        Path source = Files.createDirectory(temporaryDirectory.resolve("source"));
        Path vault = source.resolve("wallet.qpbtq");
        Path state = source.resolve("wallet.qpstate");
        BtqSeedVault.create(vault, BtqNetwork.REGTEST, master, PASSWORD, new SecureRandom());
        assertEquals(0, BtqWalletStateStore.reserveNext(
                state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE));
        assertEquals(0, BtqWalletStateStore.reserveNext(
                state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.CHANGE));

        Path backup = temporaryDirectory.resolve("wallet.qpbackup");
        BtqCustodyBackup.write(vault, state, backup, BtqNetwork.REGTEST, master);
        Path restored = Files.createDirectory(temporaryDirectory.resolve("restored"));
        Path restoredVault = restored.resolve("wallet.qpbtq");
        Path restoredState = restored.resolve("wallet.qpstate");
        BtqCustodyBackup.restore(backup, restoredVault, restoredState, BtqNetwork.REGTEST, PASSWORD);
        BtqCustodyBackup.restore(backup, restoredVault, restoredState, BtqNetwork.REGTEST, PASSWORD);

        try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(
                restoredVault, BtqNetwork.REGTEST, PASSWORD)) {
            byte[] restoredMaster = unlocked.copyMasterSecret();
            try {
                assertArrayEquals(master, restoredMaster);
                assertEquals(new BtqWalletStateStore.State(1, 1), BtqWalletStateStore.inspect(
                        restoredState, restoredMaster, BtqNetwork.REGTEST));
            } finally {
                Arrays.fill(restoredMaster, (byte)0);
            }
        }

        byte[] tampered = Files.readAllBytes(backup);
        tampered[tampered.length - 1] ^= 1;
        Path changed = temporaryDirectory.resolve("tampered.qpbackup");
        Files.write(changed, tampered);
        Path rejected = Files.createDirectory(temporaryDirectory.resolve("rejected"));
        assertThrows(IOException.class, () -> BtqCustodyBackup.restore(changed,
                rejected.resolve("wallet.qpbtq"), rejected.resolve("wallet.qpstate"),
                BtqNetwork.REGTEST, PASSWORD));
        assertFalse(Files.exists(rejected.resolve("wallet.qpbtq")));
        assertFalse(Files.exists(rejected.resolve("wallet.qpstate")));

        Path collision = Files.createDirectory(temporaryDirectory.resolve("collision"));
        Files.write(collision.resolve("wallet.qpbtq"), new byte[89]);
        assertThrows(IOException.class, () -> BtqCustodyBackup.restore(backup,
                collision.resolve("wallet.qpbtq"), collision.resolve("wallet.qpstate"),
                BtqNetwork.REGTEST, PASSWORD));
        assertFalse(Files.exists(collision.resolve("wallet.qpstate")),
                "restore must preflight both targets before installing either");
        Arrays.fill(master, (byte)0);
    }
}
