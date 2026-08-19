// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

class BtqSeedVaultTest {
    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

    @TempDir
    Path temporaryDirectory;

    @Test
    void encryptedSeedRoundTripsAndLocks() throws Exception {
        Path vault = temporaryDirectory.resolve("wallet.qbtq");
        byte[] master = masterSecret();
        BtqSeedVault.create(vault, BtqNetwork.REGTEST, master, PASSWORD, new SecureRandom());

        assertTrue(Files.isRegularFile(vault));
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(vault);
            assertFalse(permissions.contains(PosixFilePermission.GROUP_READ));
            assertFalse(permissions.contains(PosixFilePermission.OTHERS_READ));
        } catch(UnsupportedOperationException ignored) {
            // Platform ACL verification is a packaging test.
        }

        try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vault, BtqNetwork.REGTEST, PASSWORD)) {
            assertEquals(BtqNetwork.REGTEST, unlocked.network());
            byte[] copy = unlocked.copyMasterSecret();
            assertArrayEquals(master, copy);
            copy[0] ^= 1;
            assertArrayEquals(master, unlocked.copyMasterSecret());
            assertFalse(unlocked.isClosed());
        }

        BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vault, BtqNetwork.REGTEST, PASSWORD);
        unlocked.close();
        assertTrue(unlocked.isClosed());
        assertThrows(IllegalStateException.class, unlocked::copyMasterSecret);
    }

    @Test
    void authenticationNetworkAndOverwriteFailuresAreClosed() throws Exception {
        Path vault = temporaryDirectory.resolve("wallet.qbtq");
        byte[] master = masterSecret();
        BtqSeedVault.create(vault, BtqNetwork.MAINNET, master, PASSWORD, new SecureRandom());

        IOException wrongPassword = assertThrows(IOException.class,
                () -> BtqSeedVault.open(vault, BtqNetwork.MAINNET, "this password is wrong".toCharArray()));
        assertEquals("custody vault authentication failed", wrongPassword.getMessage());
        assertThrows(IOException.class, () -> BtqSeedVault.open(vault, BtqNetwork.TESTNET, PASSWORD));
        assertThrows(IOException.class,
                () -> BtqSeedVault.create(vault, BtqNetwork.MAINNET, master, PASSWORD, new SecureRandom()));
    }

    @Test
    void tamperingTruncationAndTrailingDataAreRejected() throws Exception {
        Path vault = temporaryDirectory.resolve("wallet.qbtq");
        BtqSeedVault.create(vault, BtqNetwork.SIGNET, masterSecret(), PASSWORD, new SecureRandom());
        byte[] encoded = Files.readAllBytes(vault);

        Path tampered = copyWithOwnerPermissions(vault, "tampered.qbtq");
        byte[] changed = encoded.clone();
        changed[changed.length - 1] ^= 1;
        Files.write(tampered, changed);
        assertThrows(IOException.class, () -> BtqSeedVault.open(tampered, BtqNetwork.SIGNET, PASSWORD));

        Path truncated = copyWithOwnerPermissions(vault, "truncated.qbtq");
        Files.write(truncated, Arrays.copyOf(encoded, encoded.length - 1));
        assertThrows(IOException.class, () -> BtqSeedVault.open(truncated, BtqNetwork.SIGNET, PASSWORD));

        Path trailing = copyWithOwnerPermissions(vault, "trailing.qbtq");
        Files.write(trailing, Arrays.copyOf(encoded, encoded.length + 1));
        assertThrows(IOException.class, () -> BtqSeedVault.open(trailing, BtqNetwork.SIGNET, PASSWORD));
    }

    @Test
    void weakPasswordsAndSymlinksAreRejected() throws Exception {
        Path vault = temporaryDirectory.resolve("wallet.qbtq");
        assertThrows(IllegalArgumentException.class,
                () -> BtqSeedVault.create(vault, BtqNetwork.REGTEST, masterSecret(), "too short".toCharArray(), new SecureRandom()));

        BtqSeedVault.create(vault, BtqNetwork.REGTEST, masterSecret(), PASSWORD, new SecureRandom());
        Path symlink = temporaryDirectory.resolve("linked.qbtq");
        try {
            Files.createSymbolicLink(symlink, vault.getFileName());
            assertThrows(IOException.class, () -> BtqSeedVault.open(symlink, BtqNetwork.REGTEST, PASSWORD));
        } catch(UnsupportedOperationException ignored) {
            // Platform has no symlink support.
        }
    }

    @Test
    void concurrentCreationNeverReplacesTheWinner() throws Exception {
        Path vault = temporaryDirectory.resolve("raced.qbtq");
        byte[] first = masterSecret();
        byte[] second = masterSecret();
        second[0] ^= 0x55;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> firstResult = executor.submit(() -> createAfter(start, vault, first));
            Future<Boolean> secondResult = executor.submit(() -> createAfter(start, vault, second));
            start.countDown();
            assertNotEquals(firstResult.get(), secondResult.get(), "exactly one creator must win");
            try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(
                    vault, BtqNetwork.REGTEST, PASSWORD)) {
                byte[] stored = unlocked.copyMasterSecret();
                assertTrue(Arrays.equals(first, stored) || Arrays.equals(second, stored));
            }
        } finally {
            executor.shutdownNow();
        }
    }

    private static boolean createAfter(CountDownLatch start, Path vault, byte[] master) throws Exception {
        start.await();
        try {
            BtqSeedVault.create(vault, BtqNetwork.REGTEST, master, PASSWORD, new SecureRandom());
            return true;
        } catch(IOException expected) {
            return false;
        }
    }

    private Path copyWithOwnerPermissions(Path source, String name) throws IOException {
        Path copy = temporaryDirectory.resolve(name);
        Files.copy(source, copy, StandardCopyOption.COPY_ATTRIBUTES);
        try {
            Files.setPosixFilePermissions(copy, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch(UnsupportedOperationException ignored) {
            // Platform ACL verification is a packaging test.
        }
        return copy;
    }

    private static byte[] masterSecret() {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)(0xa0 + i);
        }
        return master;
    }
}
