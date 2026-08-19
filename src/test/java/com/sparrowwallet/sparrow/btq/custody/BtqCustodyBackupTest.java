// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class BtqCustodyBackupTest {
    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

    @TempDir
    Path temporaryDirectory;

    @Test
    void refusesVaultReplacementAfterUnlock() throws Exception {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        byte[] replacementMaster = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        Arrays.fill(master, (byte)0x11);
        Arrays.fill(replacementMaster, (byte)0x22);
        Path vault = temporaryDirectory.resolve("wallet.qpbtq");
        Path replacement = temporaryDirectory.resolve("replacement.qpbtq");
        Path state = temporaryDirectory.resolve("wallet.qpstate");
        BtqSeedVault.create(vault, BtqNetwork.REGTEST, master, PASSWORD, new SecureRandom());
        BtqSeedVault.create(replacement, BtqNetwork.REGTEST, replacementMaster, PASSWORD, new SecureRandom());
        BtqWalletStateStore.initializeNew(state, master, BtqNetwork.REGTEST);

        try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vault, BtqNetwork.REGTEST, PASSWORD)) {
            Files.write(vault, Files.readAllBytes(replacement));
            assertThrows(IOException.class, () -> BtqCustodyBackup.write(vault,
                    unlocked.copyAuthenticatedEncoding(), state, temporaryDirectory.resolve("unsafe.qpbackup"),
                    BtqNetwork.REGTEST, master));
        } finally {
            Arrays.fill(master, (byte)0);
            Arrays.fill(replacementMaster, (byte)0);
        }
    }

    @Test
    void authenticatedBackupRestoresBothCustodyFilesAndIsRetrySafe() throws Exception {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) master[i] = (byte)(0x40 + i);
        Path source = Files.createDirectory(temporaryDirectory.resolve("source"));
        Path vault = source.resolve("wallet.qpbtq");
        Path state = source.resolve("wallet.qpstate");
        BtqSeedVault.create(vault, BtqNetwork.REGTEST, master, PASSWORD, new SecureRandom());
        BtqWalletStateStore.initializeNew(state, master, BtqNetwork.REGTEST);
        assertEquals(0, BtqWalletStateStore.reserveNext(
                state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE));
        assertEquals(0, BtqWalletStateStore.reserveNext(
                state, master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.CHANGE));

        Path backup = temporaryDirectory.resolve("wallet.qpbackup");
        try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vault, BtqNetwork.REGTEST, PASSWORD)) {
            BtqCustodyBackup.write(vault, unlocked.copyAuthenticatedEncoding(), state, backup,
                    BtqNetwork.REGTEST, master);
        }
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

    @Test
    void restoresBackupsWhoseModeIsNotOwnerOnly() throws Exception {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        Arrays.fill(master, (byte)0x5a);
        Path source = Files.createDirectory(temporaryDirectory.resolve("relaxed-source"));
        Path vault = source.resolve("wallet.qpbtq");
        Path state = source.resolve("wallet.qpstate");
        BtqSeedVault.create(vault, BtqNetwork.REGTEST, master, PASSWORD, new SecureRandom());
        BtqWalletStateStore.initializeNew(state, master, BtqNetwork.REGTEST);
        Path backup = temporaryDirectory.resolve("relaxed.qpbackup");
        try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vault, BtqNetwork.REGTEST, PASSWORD)) {
            BtqCustodyBackup.write(vault, unlocked.copyAuthenticatedEncoding(), state, backup,
                    BtqNetwork.REGTEST, master);
        }

        // A container that travelled through cloud storage (0644) or an archive (0400) must still restore:
        // it is ciphertext plus a MAC, and the restored vault/state are installed owner-only regardless.
        for(String mode : new String[] {"rw-r--r--", "r--------"}) {
            Path copy = temporaryDirectory.resolve("copy-" + mode.replace("-", "_") + ".qpbackup");
            Files.write(copy, Files.readAllBytes(backup));
            Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString(mode));
            Path restored = Files.createDirectory(temporaryDirectory.resolve("restored-" + mode.replace("-", "_")));
            Path restoredVault = restored.resolve("wallet.qpbtq");
            Path restoredState = restored.resolve("wallet.qpstate");
            BtqCustodyBackup.restore(copy, restoredVault, restoredState, BtqNetwork.REGTEST, PASSWORD);
            assertArrayEquals(Files.readAllBytes(vault), Files.readAllBytes(restoredVault));
            assertEquals(PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(restoredVault),
                    "restored custody files must be installed owner-only");
            assertEquals(PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(restoredState),
                    "restored custody files must be installed owner-only");
        }
        Arrays.fill(master, (byte)0);
    }

    @Test
    void refusesASymlinkedBackupContainer() throws Exception {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        Arrays.fill(master, (byte)0x6b);
        Path source = Files.createDirectory(temporaryDirectory.resolve("symlink-source"));
        Path vault = source.resolve("wallet.qpbtq");
        Path state = source.resolve("wallet.qpstate");
        BtqSeedVault.create(vault, BtqNetwork.REGTEST, master, PASSWORD, new SecureRandom());
        BtqWalletStateStore.initializeNew(state, master, BtqNetwork.REGTEST);
        Path backup = temporaryDirectory.resolve("linked-target.qpbackup");
        try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vault, BtqNetwork.REGTEST, PASSWORD)) {
            BtqCustodyBackup.write(vault, unlocked.copyAuthenticatedEncoding(), state, backup,
                    BtqNetwork.REGTEST, master);
        }
        Path link = temporaryDirectory.resolve("linked.qpbackup");
        Files.createSymbolicLink(link, backup);
        Path restored = Files.createDirectory(temporaryDirectory.resolve("symlink-restored"));

        IOException failure = assertThrows(IOException.class, () -> BtqCustodyBackup.restore(link,
                restored.resolve("wallet.qpbtq"), restored.resolve("wallet.qpstate"),
                BtqNetwork.REGTEST, PASSWORD));

        assertTrue(failure.getMessage().contains("is not a regular file"), failure.getMessage());
        assertFalse(Files.exists(restored.resolve("wallet.qpbtq")));
        Arrays.fill(master, (byte)0);
    }

    @Test
    void pinsTheBackupHeaderNetworkIds() throws Exception {
        // Stable wire ids, not enum ordinals: existing backups must keep parsing across enum edits.
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        Arrays.fill(master, (byte)0x7c);
        int networkIdOffset = 8 + Integer.BYTES;
        for(BtqNetwork network : BtqNetwork.values()) {
            int expected = switch(network) {
                case MAINNET -> 0;
                case TESTNET -> 1;
                case SIGNET -> 2;
                case REGTEST -> 3;
            };
            Path directory = Files.createDirectory(temporaryDirectory.resolve("net-" + network.rpcChain()));
            Path vault = directory.resolve("wallet.qpbtq");
            Path state = directory.resolve("wallet.qpstate");
            BtqSeedVault.create(vault, network, master, PASSWORD, new SecureRandom());
            BtqWalletStateStore.initializeNew(state, master, network);
            Path backup = directory.resolve("wallet.qpbackup");
            try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vault, network, PASSWORD)) {
                BtqCustodyBackup.write(vault, unlocked.copyAuthenticatedEncoding(), state, backup, network, master);
            }

            assertEquals((byte)expected, Files.readAllBytes(backup)[networkIdOffset],
                    "backup header network id for " + network);

            Path restored = Files.createDirectory(temporaryDirectory.resolve("net-restored-" + network.rpcChain()));
            BtqCustodyBackup.restore(backup, restored.resolve("wallet.qpbtq"),
                    restored.resolve("wallet.qpstate"), network, PASSWORD);
            for(BtqNetwork other : BtqNetwork.values()) {
                if(other == network) continue;
                Path wrong = Files.createDirectory(
                        temporaryDirectory.resolve("net-wrong-" + network.rpcChain() + "-" + other.rpcChain()));
                assertThrows(IOException.class, () -> BtqCustodyBackup.restore(backup,
                        wrong.resolve("wallet.qpbtq"), wrong.resolve("wallet.qpstate"), other, PASSWORD));
            }
        }
        Arrays.fill(master, (byte)0);
    }
}
