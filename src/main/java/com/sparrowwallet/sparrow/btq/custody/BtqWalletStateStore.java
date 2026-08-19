// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * Authenticated, monotonically increasing receive/change address state.
 *
 * <p>An index is persisted before it is returned, so crashes may create gaps
 * but cannot cause normal address reuse. This is a strict v1 state format and
 * has no import path for Sparrow, Core, or earlier Qparrow prototypes.</p>
 */
public final class BtqWalletStateStore {
    private static final byte[] MAGIC = {'Q', 'P', 'B', 'T', 'Q', 'S', 'T', 'A'};
    private static final byte[] ID_DOMAIN = "Qparrow/BTQ/WalletId/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] AUTH_DOMAIN = "Qparrow/BTQ/StateAuth/v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int WALLET_ID_BYTES = 16;
    private static final int MAC_BYTES = 32;
    private static final int BODY_BYTES = MAGIC.length + Integer.BYTES + 1 + WALLET_ID_BYTES + Integer.BYTES + Integer.BYTES;
    private static final int FILE_BYTES = BODY_BYTES + MAC_BYTES;
    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private BtqWalletStateStore() {
    }

    /** Atomically reserve and return the next address index for a chain. */
    public static int reserveNext(Path stateFile, byte[] masterSecret, BtqNetwork network,
                                  BtqCustodySpec.Chain chain) throws IOException {
        Objects.requireNonNull(stateFile, "stateFile");
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(chain, "chain");
        BtqCustodySpec.requireLength(masterSecret, BtqCustodySpec.MASTER_SECRET_BYTES, "master secret");

        Path absolute = stateFile.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if(parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("wallet-state parent directory does not exist");
        }
        Path lockPath = parent.resolve(absolute.getFileName() + ".lock");
        byte[] walletId = derive(masterSecret, network, ID_DOMAIN, WALLET_ID_BYTES);
        byte[] authKey = derive(masterSecret, network, AUTH_DOMAIN, MAC_BYTES);
        try(FileChannel lockChannel = openLockFile(lockPath); FileLock ignored = lockChannel.lock()) {
            hardenPermissions(lockPath);
            State current = Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)
                    ? read(absolute, network, walletId, authKey)
                    : new State(0, 0);
            int reserved = chain == BtqCustodySpec.Chain.RECEIVE ? current.nextReceive : current.nextChange;
            if(reserved == BtqCustodySpec.MAX_INDEX) {
                throw new IOException("wallet derivation index is exhausted");
            }
            State updated = chain == BtqCustodySpec.Chain.RECEIVE
                    ? new State(reserved + 1, current.nextChange)
                    : new State(current.nextReceive, reserved + 1);
            write(absolute, network, walletId, authKey, updated);
            return reserved;
        } finally {
            Arrays.fill(walletId, (byte)0);
            Arrays.fill(authKey, (byte)0);
        }
    }

    public static State inspect(Path stateFile, byte[] masterSecret, BtqNetwork network) throws IOException {
        Objects.requireNonNull(stateFile, "stateFile");
        Objects.requireNonNull(network, "network");
        BtqCustodySpec.requireLength(masterSecret, BtqCustodySpec.MASTER_SECRET_BYTES, "master secret");
        byte[] walletId = derive(masterSecret, network, ID_DOMAIN, WALLET_ID_BYTES);
        byte[] authKey = derive(masterSecret, network, AUTH_DOMAIN, MAC_BYTES);
        try {
            return read(stateFile.toAbsolutePath().normalize(), network, walletId, authKey);
        } finally {
            Arrays.fill(walletId, (byte)0);
            Arrays.fill(authKey, (byte)0);
        }
    }

    private static State read(Path path, BtqNetwork network, byte[] walletId, byte[] authKey) throws IOException {
        if(!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("wallet state is not a regular file");
        }
        requireOwnerOnlyPermissions(path);
        byte[] encoded = Files.readAllBytes(path);
        try {
            if(encoded.length != FILE_BYTES) throw new IOException("invalid wallet-state length");
            byte[] body = Arrays.copyOf(encoded, BODY_BYTES);
            byte[] storedMac = Arrays.copyOfRange(encoded, BODY_BYTES, FILE_BYTES);
            byte[] actualMac = hmacSha256(authKey, body);
            try {
                if(!java.security.MessageDigest.isEqual(storedMac, actualMac)) {
                    throw new IOException("wallet-state authentication failed");
                }
            } finally {
                Arrays.fill(storedMac, (byte)0);
                Arrays.fill(actualMac, (byte)0);
            }
            ByteBuffer buffer = ByteBuffer.wrap(body);
            byte[] magic = new byte[MAGIC.length];
            buffer.get(magic);
            if(!Arrays.equals(magic, MAGIC) || buffer.getInt() != BtqCustodySpec.VERSION
                    || buffer.get() != networkId(network)) {
                throw new IOException("wallet-state header does not match this wallet");
            }
            byte[] storedId = new byte[WALLET_ID_BYTES];
            buffer.get(storedId);
            if(!java.security.MessageDigest.isEqual(storedId, walletId)) {
                throw new IOException("wallet-state belongs to a different wallet");
            }
            int nextReceive = buffer.getInt();
            int nextChange = buffer.getInt();
            if(nextReceive < 0 || nextChange < 0) throw new IOException("invalid wallet-state index");
            return new State(nextReceive, nextChange);
        } finally {
            Arrays.fill(encoded, (byte)0);
        }
    }

    private static void write(Path target, BtqNetwork network, byte[] walletId, byte[] authKey, State state)
            throws IOException {
        byte[] body = ByteBuffer.allocate(BODY_BYTES)
                .put(MAGIC)
                .putInt(BtqCustodySpec.VERSION)
                .put(networkId(network))
                .put(walletId)
                .putInt(state.nextReceive)
                .putInt(state.nextChange)
                .array();
        byte[] mac = hmacSha256(authKey, body);
        byte[] encoded = ByteBuffer.allocate(FILE_BYTES).put(body).put(mac).array();
        Path temporary = createOwnerOnlyTempFile(target.getParent(), "." + target.getFileName() + ".", ".tmp");
        boolean moved = false;
        try {
            try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(ByteBuffer.wrap(encoded));
                channel.force(true);
            }
            hardenPermissions(temporary);
            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch(java.nio.file.AtomicMoveNotSupportedException e) {
                throw new IOException("wallet-state filesystem does not support atomic replacement", e);
            }
            moved = true;
            forceDirectory(target.getParent());
        } finally {
            Arrays.fill(body, (byte)0);
            Arrays.fill(mac, (byte)0);
            Arrays.fill(encoded, (byte)0);
            if(!moved) Files.deleteIfExists(temporary);
        }
    }

    private static byte[] derive(byte[] masterSecret, BtqNetwork network, byte[] domain, int length) {
        byte[] networkBytes = network.rpcChain().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] input = ByteBuffer.allocate(domain.length + 1 + networkBytes.length)
                .put(domain).put((byte)0).put(networkBytes).array();
        byte[] full = hmacSha256(masterSecret, input);
        Arrays.fill(input, (byte)0);
        byte[] result = Arrays.copyOf(full, length);
        Arrays.fill(full, (byte)0);
        return result;
    }

    private static byte[] hmacSha256(byte[] key, byte[] input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(input);
        } catch(GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }

    private static FileChannel openLockFile(Path path) throws IOException {
        if(Files.exists(path, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("wallet-state lock is not a regular file");
        }
        try {
            return FileChannel.open(path,
                    Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE),
                    PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        } catch(UnsupportedOperationException e) {
            FileChannel channel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            hardenPermissions(path);
            return channel;
        }
    }

    private static Path createOwnerOnlyTempFile(Path parent, String prefix, String suffix) throws IOException {
        try {
            return Files.createTempFile(parent, prefix, suffix, PosixFilePermissions.asFileAttribute(OWNER_ONLY));
        } catch(UnsupportedOperationException e) {
            Path temporary = Files.createTempFile(parent, prefix, suffix);
            hardenPermissions(temporary);
            return temporary;
        }
    }

    private static void hardenPermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch(UnsupportedOperationException ignored) {
            // Platform ACL validation belongs in packaging tests.
        }
    }

    private static void requireOwnerOnlyPermissions(Path path) throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
            for(PosixFilePermission permission : permissions) {
                if(permission != PosixFilePermission.OWNER_READ && permission != PosixFilePermission.OWNER_WRITE) {
                    throw new IOException("wallet-state permissions are not owner-only");
                }
            }
        } catch(UnsupportedOperationException ignored) {
            // Platform ACL validation belongs in packaging tests.
        }
    }

    private static void forceDirectory(Path directory) {
        try(FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch(IOException | UnsupportedOperationException ignored) {
            // Best effort on filesystems which cannot open directories.
        }
    }

    private static byte networkId(BtqNetwork network) {
        return switch(network) {
            case MAINNET -> 0;
            case TESTNET -> 1;
            case SIGNET -> 2;
            case REGTEST -> 3;
        };
    }

    public record State(int nextReceive, int nextChange) {
        public State {
            if(nextReceive < 0 || nextChange < 0) throw new IllegalArgumentException("negative wallet index");
        }
    }
}
