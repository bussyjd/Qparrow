// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

/** Stores only non-secret BTQ node metadata in a user-private properties file. */
public final class BtqNodeProfileStore {
    public static final String FILE_NAME = "btq-node.properties";

    private final Path file;

    public BtqNodeProfileStore(Path configDirectory) {
        this.file = Objects.requireNonNull(configDirectory, "configDirectory").resolve(FILE_NAME);
    }

    public Optional<BtqNodeProfile> load() throws IOException {
        if(!Files.isRegularFile(file)) {
            return Optional.empty();
        }
        Properties properties = new Properties();
        try(InputStream input = Files.newInputStream(file)) {
            properties.load(input);
        }
        for(String key : properties.stringPropertyNames()) {
            String normalized = key.toLowerCase();
            if(normalized.contains("password") || normalized.contains("authorization") || normalized.contains("secret")) {
                throw new IOException("Refusing BTQ profile containing persisted credentials");
            }
        }

        try {
            BtqAuthMode authMode = BtqAuthMode.valueOf(required(properties, "auth.mode"));
            String cookie = properties.getProperty("cookie.file", "");
            return Optional.of(new BtqNodeProfile(
                    URI.create(required(properties, "rpc.uri")),
                    required(properties, "wallet.name"),
                    BtqNetwork.valueOf(required(properties, "network")),
                    authMode,
                    properties.getProperty("rpc.username", ""),
                    cookie.isBlank() ? null : Path.of(cookie),
                    Duration.ofSeconds(Long.parseLong(properties.getProperty("timeout.seconds", "30")))
            ));
        } catch(RuntimeException e) {
            throw new IOException("Invalid BTQ node profile " + file, e);
        }
    }

    public void save(BtqNodeProfile profile) throws IOException {
        Objects.requireNonNull(profile, "profile");
        Files.createDirectories(file.getParent());
        setOwnerOnly(file.getParent(), true);

        Properties properties = new Properties();
        properties.setProperty("rpc.uri", profile.rpcUri().toString());
        properties.setProperty("wallet.name", profile.walletName());
        properties.setProperty("network", profile.network().name());
        properties.setProperty("auth.mode", profile.authMode().name());
        properties.setProperty("timeout.seconds", Long.toString(profile.requestTimeout().toSeconds()));
        if(!profile.rpcUsername().isBlank()) {
            properties.setProperty("rpc.username", profile.rpcUsername());
        }
        if(profile.cookieFile() != null) {
            properties.setProperty("cookie.file", profile.cookieFile().toString());
        }

        Path temporary = Files.createTempFile(file.getParent(), ".btq-node-", ".tmp");
        try {
            setOwnerOnly(temporary, false);
            try(OutputStream output = Files.newOutputStream(temporary)) {
                properties.store(output, "Qparrow public BTQ Core connection metadata; non-secret settings only");
            }
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch(AtomicMoveNotSupportedException e) {
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
            }
            setOwnerOnly(file, false);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    public Path file() {
        return file;
    }

    private static String required(Properties properties, String key) {
        String value = properties.getProperty(key);
        if(value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing property " + key);
        }
        return value;
    }

    private static void setOwnerOnly(Path path, boolean directory) throws IOException {
        try {
            Set<PosixFilePermission> permissions = directory
                    ? EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
                    : EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(path, permissions);
        } catch(UnsupportedOperationException ignored) {
            // Windows and other non-POSIX file systems use their native ACLs.
        }
    }
}
