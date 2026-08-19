// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/** Strict container for one encrypted vault and its authenticated address counters. */
public final class BtqCustodyBackup {
    private static final Object PROCESS_LOCK = new Object();
    private static final byte[] MAGIC = {'Q', 'P', 'B', 'T', 'Q', 'B', 'A', 'K'};
    private static final int VAULT_BYTES = 89;
    private static final int STATE_BYTES = 69;
    private static final int HEADER_BYTES = MAGIC.length + Integer.BYTES + 1 + Integer.BYTES + Integer.BYTES;
    private static final int FILE_BYTES = HEADER_BYTES + VAULT_BYTES + STATE_BYTES;
    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private BtqCustodyBackup() {
    }

    public static void write(Path vault, Path state, Path target, BtqNetwork network,
                             byte[] masterSecret) throws IOException {
        Objects.requireNonNull(network, "network");
        BtqCustodySpec.requireLength(masterSecret, BtqCustodySpec.MASTER_SECRET_BYTES, "master secret");
        byte[] vaultBytes = readExact(vault, VAULT_BYTES, "custody vault");
        byte[] stateBytes = readExact(state, STATE_BYTES, "wallet state");
        try {
            BtqWalletStateStore.inspect(state, masterSecret, network);
            byte[] encoded = ByteBuffer.allocate(FILE_BYTES).put(MAGIC).putInt(BtqCustodySpec.VERSION)
                    .put(networkId(network)).putInt(vaultBytes.length).putInt(stateBytes.length)
                    .put(vaultBytes).put(stateBytes).array();
            writeNew(target, encoded, ".backup.lock");
            Arrays.fill(encoded, (byte)0);
        } finally {
            Arrays.fill(vaultBytes, (byte)0);
            Arrays.fill(stateBytes, (byte)0);
        }
    }

    /** Validate both embedded files before installing either; existing identical parts make retry idempotent. */
    public static void restore(Path backup, Path targetVault, Path targetState, BtqNetwork expectedNetwork,
                               char[] password) throws IOException {
        Objects.requireNonNull(expectedNetwork, "expectedNetwork");
        byte[] encoded = readExact(backup, FILE_BYTES, "custody backup");
        byte[] vaultBytes = null;
        byte[] stateBytes = null;
        Path vaultTemp = null;
        Path stateTemp = null;
        try {
            ByteBuffer buffer = ByteBuffer.wrap(encoded);
            byte[] magic = new byte[MAGIC.length];
            buffer.get(magic);
            if(!Arrays.equals(magic, MAGIC) || buffer.getInt() != BtqCustodySpec.VERSION
                    || networkFromId(buffer.get()) != expectedNetwork
                    || buffer.getInt() != VAULT_BYTES || buffer.getInt() != STATE_BYTES) {
                throw new IOException("invalid or wrong-network custody backup header");
            }
            vaultBytes = new byte[VAULT_BYTES];
            stateBytes = new byte[STATE_BYTES];
            buffer.get(vaultBytes);
            buffer.get(stateBytes);

            Path vaultTarget = absoluteWithParent(targetVault, "vault");
            Path stateTarget = absoluteWithParent(targetState, "state");
            if(!vaultTarget.getParent().equals(stateTarget.getParent())) {
                throw new IOException("vault and state restore targets must share a directory");
            }
            Path parent = vaultTarget.getParent();
            vaultTemp = writeTemp(parent, ".qparrow-restore-vault-", vaultBytes);
            stateTemp = writeTemp(parent, ".qparrow-restore-state-", stateBytes);
            try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vaultTemp, expectedNetwork, password)) {
                byte[] master = unlocked.copyMasterSecret();
                try {
                    BtqWalletStateStore.inspect(stateTemp, master, expectedNetwork);
                } finally {
                    Arrays.fill(master, (byte)0);
                }
            }

            Path lockPath = parent.resolve(vaultTarget.getFileName() + ".restore.lock");
            synchronized(PROCESS_LOCK) {
                try(FileChannel lockChannel = FileChannel.open(lockPath, StandardOpenOption.CREATE,
                        StandardOpenOption.WRITE); java.nio.channels.FileLock ignored = lockChannel.lock()) {
                    harden(lockPath);
                    requireAbsentOrMatching(stateTarget, stateBytes);
                    requireAbsentOrMatching(vaultTarget, vaultBytes);
                    installOrVerify(stateTemp, stateTarget, stateBytes);
                    stateTemp = null;
                    installOrVerify(vaultTemp, vaultTarget, vaultBytes);
                    vaultTemp = null;
                    forceDirectory(parent);
                }
            }
        } finally {
            Arrays.fill(encoded, (byte)0);
            if(vaultBytes != null) Arrays.fill(vaultBytes, (byte)0);
            if(stateBytes != null) Arrays.fill(stateBytes, (byte)0);
            if(vaultTemp != null) Files.deleteIfExists(vaultTemp);
            if(stateTemp != null) Files.deleteIfExists(stateTemp);
        }
    }

    private static void installOrVerify(Path temporary, Path target, byte[] expected) throws IOException {
        if(Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            if(!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)
                    || !Arrays.equals(Files.readAllBytes(target), expected)) {
                throw new IOException("refusing to replace non-matching existing custody file " + target);
            }
            harden(target);
            Files.deleteIfExists(temporary);
            return;
        }
        Files.move(temporary, target);
        harden(target);
    }

    private static void requireAbsentOrMatching(Path target, byte[] expected) throws IOException {
        if(Files.exists(target, LinkOption.NOFOLLOW_LINKS)
                && (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)
                || !Arrays.equals(Files.readAllBytes(target), expected))) {
            throw new IOException("refusing to replace non-matching existing custody file " + target);
        }
    }

    private static void writeNew(Path target, byte[] bytes, String lockSuffix) throws IOException {
        Path absolute = absoluteWithParent(target, "backup");
        Path lockPath = absolute.getParent().resolve(absolute.getFileName() + lockSuffix);
        synchronized(PROCESS_LOCK) {
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE); java.nio.channels.FileLock ignored = channel.lock()) {
                harden(lockPath);
                if(Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
                    throw new IOException("refusing to overwrite an existing custody backup");
                }
                Path temporary = writeTemp(absolute.getParent(), ".qparrow-backup-", bytes);
                try {
                    Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
                    harden(absolute);
                    forceDirectory(absolute.getParent());
                } finally {
                    Files.deleteIfExists(temporary);
                }
            }
        }
    }

    private static byte[] readExact(Path source, int expectedLength, String name) throws IOException {
        Path absolute = Objects.requireNonNull(source, name).toAbsolutePath().normalize();
        if(!Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(name + " is not a regular file");
        }
        byte[] bytes = Files.readAllBytes(absolute);
        if(bytes.length != expectedLength) {
            Arrays.fill(bytes, (byte)0);
            throw new IOException("invalid " + name + " length");
        }
        return bytes;
    }

    private static Path absoluteWithParent(Path path, String name) throws IOException {
        Path absolute = Objects.requireNonNull(path, name).toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if(parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException(name + " parent directory does not exist");
        }
        return absolute;
    }

    private static Path writeTemp(Path parent, String prefix, byte[] bytes) throws IOException {
        Path temporary;
        try {
            temporary = Files.createTempFile(parent, prefix, ".tmp",
                    PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        } catch(UnsupportedOperationException e) {
            temporary = Files.createTempFile(parent, prefix, ".tmp");
        }
        harden(temporary);
        try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            channel.write(ByteBuffer.wrap(bytes));
            channel.force(true);
        }
        return temporary;
    }

    private static void harden(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch(UnsupportedOperationException ignored) {
            // Native ACL enforcement is covered by platform packaging tests.
        }
    }

    private static void forceDirectory(Path parent) {
        try(FileChannel channel = FileChannel.open(parent, StandardOpenOption.READ)) {
            channel.force(true);
        } catch(IOException | UnsupportedOperationException ignored) {
            // Best effort on platforms that do not permit directory channels.
        }
    }

    private static byte networkId(BtqNetwork network) {
        return (byte)network.ordinal();
    }

    private static BtqNetwork networkFromId(byte id) throws IOException {
        if(id < 0 || id >= BtqNetwork.values().length) throw new IOException("unknown backup network id");
        return BtqNetwork.values()[id];
    }
}
