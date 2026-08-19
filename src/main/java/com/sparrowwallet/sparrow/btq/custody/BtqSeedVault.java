// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * Strict Qparrow v1 encrypted seed file.
 *
 * <p>The format is intentionally fixed-width and version-exact. Supporting a
 * future format means writing a new version, not accumulating parsers for
 * Sparrow databases, Core wallets, descriptors, xprvs, or prototype files.</p>
 */
public final class BtqSeedVault {
    private static final Object PROCESS_CREATE_LOCK = new Object();
    private static final byte[] MAGIC = {'Q', 'P', 'B', 'T', 'Q', 'V', 'L', 'T'};
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BYTES = 16;
    private static final int HEADER_BYTES = MAGIC.length + Integer.BYTES + 1 + SALT_BYTES + NONCE_BYTES;
    private static final int CIPHERTEXT_BYTES = BtqCustodySpec.MASTER_SECRET_BYTES + GCM_TAG_BYTES;
    private static final int FILE_BYTES = HEADER_BYTES + CIPHERTEXT_BYTES;
    private static final int MIN_PASSWORD_CHARS = 12;

    // These are part of format v1. Changing them requires a new vault version.
    private static final int ARGON2_MEMORY_KIB = 64 * 1024;
    private static final int ARGON2_ITERATIONS = 3;
    private static final int ARGON2_PARALLELISM = 1;
    private static final int KEY_BYTES = 32;

    private static final Set<PosixFilePermission> OWNER_ONLY = EnumSet.of(
            PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

    private BtqSeedVault() {
    }

    public static void create(Path target, BtqNetwork network, byte[] masterSecret,
                              char[] password, SecureRandom random) throws IOException {
        Objects.requireNonNull(target, "target");
        Path absolute = target.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if(parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("vault parent directory does not exist");
        }
        Path lockPath = parent.resolve(absolute.getFileName() + ".create.lock");
        synchronized(PROCESS_CREATE_LOCK) {
            if(Files.exists(lockPath, LinkOption.NOFOLLOW_LINKS)
                    && !Files.isRegularFile(lockPath, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("vault creation lock is not a regular file");
            }
            try(FileChannel channel = FileChannel.open(lockPath, StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE); java.nio.channels.FileLock ignored = channel.lock()) {
                hardenPermissions(lockPath);
                createLocked(absolute, network, masterSecret, password, random);
            }
        }
    }

    private static void createLocked(Path target, BtqNetwork network, byte[] masterSecret,
                                     char[] password, SecureRandom random) throws IOException {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(random, "random");
        BtqCustodySpec.requireLength(masterSecret, BtqCustodySpec.MASTER_SECRET_BYTES, "master secret");
        requirePassword(password);

        Path absolute = target.toAbsolutePath().normalize();
        Path parent = absolute.getParent();
        if(parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("vault parent directory does not exist");
        }
        if(Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("refusing to overwrite an existing custody vault");
        }

        byte[] salt = new byte[SALT_BYTES];
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(salt);
        random.nextBytes(nonce);
        byte[] header = header(network, salt, nonce);
        byte[] key = deriveKey(password, salt);
        byte[] ciphertext;
        try {
            ciphertext = crypt(Cipher.ENCRYPT_MODE, key, nonce, header, masterSecret);
        } catch(GeneralSecurityException e) {
            throw new IOException("could not encrypt custody vault", e);
        } finally {
            Arrays.fill(key, (byte)0);
        }
        if(ciphertext.length != CIPHERTEXT_BYTES) {
            Arrays.fill(ciphertext, (byte)0);
            throw new IOException("unexpected encrypted vault length");
        }

        byte[] encoded = ByteBuffer.allocate(FILE_BYTES).put(header).put(ciphertext).array();
        Path temporary = createOwnerOnlyTempFile(parent, "." + absolute.getFileName() + ".", ".tmp");
        boolean moved = false;
        try {
            try(FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                channel.write(ByteBuffer.wrap(encoded));
                channel.force(true);
            }
            hardenPermissions(temporary);
            Files.move(temporary, absolute, StandardCopyOption.ATOMIC_MOVE);
            moved = true;
            forceDirectory(parent);
        } finally {
            Arrays.fill(encoded, (byte)0);
            Arrays.fill(ciphertext, (byte)0);
            Arrays.fill(salt, (byte)0);
            Arrays.fill(nonce, (byte)0);
            if(!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    public static UnlockedSeed open(Path source, BtqNetwork expectedNetwork, char[] password) throws IOException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(expectedNetwork, "expectedNetwork");
        requirePassword(password);
        Path absolute = source.toAbsolutePath().normalize();
        if(!Files.isRegularFile(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("custody vault is not a regular file");
        }
        requireOwnerOnlyPermissions(absolute);

        byte[] encoded = Files.readAllBytes(absolute);
        if(encoded.length != FILE_BYTES) {
            Arrays.fill(encoded, (byte)0);
            throw new IOException("invalid custody vault length");
        }

        byte[] header = Arrays.copyOfRange(encoded, 0, HEADER_BYTES);
        Header parsed;
        try {
            parsed = parseHeader(header);
        } catch(IllegalArgumentException e) {
            Arrays.fill(encoded, (byte)0);
            Arrays.fill(header, (byte)0);
            throw new IOException("invalid custody vault header", e);
        }
        if(parsed.network != expectedNetwork) {
            Arrays.fill(encoded, (byte)0);
            Arrays.fill(header, (byte)0);
            parsed.clear();
            throw new IOException("custody vault belongs to a different BTQ network");
        }

        byte[] key = deriveKey(password, parsed.salt);
        byte[] ciphertext = Arrays.copyOfRange(encoded, HEADER_BYTES, encoded.length);
        byte[] masterSecret;
        try {
            masterSecret = crypt(Cipher.DECRYPT_MODE, key, parsed.nonce, header, ciphertext);
        } catch(AEADBadTagException e) {
            throw new IOException("custody vault authentication failed");
        } catch(GeneralSecurityException e) {
            throw new IOException("could not decrypt custody vault", e);
        } finally {
            Arrays.fill(key, (byte)0);
            Arrays.fill(ciphertext, (byte)0);
            Arrays.fill(encoded, (byte)0);
            Arrays.fill(header, (byte)0);
            parsed.clear();
        }
        if(masterSecret.length != BtqCustodySpec.MASTER_SECRET_BYTES) {
            Arrays.fill(masterSecret, (byte)0);
            throw new IOException("invalid custody vault payload");
        }
        return new UnlockedSeed(expectedNetwork, masterSecret);
    }

    private static byte[] header(BtqNetwork network, byte[] salt, byte[] nonce) {
        return ByteBuffer.allocate(HEADER_BYTES)
                .put(MAGIC)
                .putInt(BtqCustodySpec.VERSION)
                .put(networkId(network))
                .put(salt)
                .put(nonce)
                .array();
    }

    private static Header parseHeader(byte[] header) {
        ByteBuffer buffer = ByteBuffer.wrap(header);
        byte[] magic = new byte[MAGIC.length];
        buffer.get(magic);
        if(!Arrays.equals(MAGIC, magic)) {
            throw new IllegalArgumentException("wrong magic");
        }
        if(buffer.getInt() != BtqCustodySpec.VERSION) {
            throw new IllegalArgumentException("unsupported vault version");
        }
        BtqNetwork network = networkFromId(buffer.get());
        byte[] salt = new byte[SALT_BYTES];
        byte[] nonce = new byte[NONCE_BYTES];
        buffer.get(salt);
        buffer.get(nonce);
        return new Header(network, salt, nonce);
    }

    private static byte[] deriveKey(char[] password, byte[] salt) {
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(ARGON2_MEMORY_KIB)
                .withIterations(ARGON2_ITERATIONS)
                .withParallelism(ARGON2_PARALLELISM)
                .withSalt(salt)
                .build();
        byte[] key = new byte[KEY_BYTES];
        try {
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(parameters);
            generator.generateBytes(password, key);
            return key;
        } finally {
            parameters.clear();
        }
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] header, byte[] input)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(header);
        return cipher.doFinal(input);
    }

    private static void requirePassword(char[] password) {
        if(password == null || password.length < MIN_PASSWORD_CHARS) {
            throw new IllegalArgumentException("custody password must contain at least " + MIN_PASSWORD_CHARS + " characters");
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

    private static BtqNetwork networkFromId(byte id) {
        return switch(id) {
            case 0 -> BtqNetwork.MAINNET;
            case 1 -> BtqNetwork.TESTNET;
            case 2 -> BtqNetwork.SIGNET;
            case 3 -> BtqNetwork.REGTEST;
            default -> throw new IllegalArgumentException("unknown network id");
        };
    }

    private static void hardenPermissions(Path path) throws IOException {
        try {
            Files.setPosixFilePermissions(path, OWNER_ONLY);
        } catch(UnsupportedOperationException ignored) {
            // ACL enforcement is platform-specific. Atomic creation still
            // prevents a partially written vault from becoming visible.
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

    private static void requireOwnerOnlyPermissions(Path path) throws IOException {
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
            if(permissions.contains(PosixFilePermission.GROUP_READ)
                    || permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
                    || permissions.contains(PosixFilePermission.OTHERS_READ)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                throw new IOException("custody vault permissions are not owner-only");
            }
        } catch(UnsupportedOperationException ignored) {
            // See hardenPermissions. Windows ACL checks belong in the
            // platform packaging gate rather than a fake POSIX abstraction.
        }
    }

    private static void forceDirectory(Path directory) {
        try(FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch(IOException | UnsupportedOperationException ignored) {
            // Best effort: not every platform permits opening directories.
        }
    }

    private static final class Header {
        private final BtqNetwork network;
        private final byte[] salt;
        private final byte[] nonce;

        private Header(BtqNetwork network, byte[] salt, byte[] nonce) {
            this.network = network;
            this.salt = salt;
            this.nonce = nonce;
        }

        private void clear() {
            Arrays.fill(salt, (byte)0);
            Arrays.fill(nonce, (byte)0);
        }
    }

    public static final class UnlockedSeed implements AutoCloseable {
        private final BtqNetwork network;
        private byte[] masterSecret;

        private UnlockedSeed(BtqNetwork network, byte[] masterSecret) {
            this.network = network;
            this.masterSecret = masterSecret;
        }

        public BtqNetwork network() {
            return network;
        }

        public synchronized byte[] copyMasterSecret() {
            if(masterSecret == null) {
                throw new IllegalStateException("custody vault is locked");
            }
            return masterSecret.clone();
        }

        public synchronized boolean isClosed() {
            return masterSecret == null;
        }

        @Override
        public synchronized void close() {
            if(masterSecret != null) {
                Arrays.fill(masterSecret, (byte)0);
                masterSecret = null;
            }
        }
    }
}
