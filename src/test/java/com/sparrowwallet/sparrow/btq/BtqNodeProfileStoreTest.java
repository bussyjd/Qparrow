// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class BtqNodeProfileStoreTest {
    @TempDir
    Path directory;

    @Test
    void roundTripsPublicCookieProfileWithoutSecrets() throws Exception {
        Path cookie = directory.resolve("core.cookie");
        BtqNodeProfile profile = new BtqNodeProfile(
                URI.create("http://127.0.0.1:18443/"),
                "qparrow_test",
                BtqNetwork.REGTEST,
                BtqAuthMode.COOKIE,
                "",
                cookie,
                Duration.ofSeconds(17));
        BtqNodeProfileStore store = new BtqNodeProfileStore(directory.resolve("config"));

        store.save(profile);
        Optional<BtqNodeProfile> loaded = store.load();

        assertEquals(Optional.of(profile), loaded);
        String persisted = Files.readString(store.file());
        assertFalse(persisted.toLowerCase().contains("password"));
        assertFalse(persisted.contains("authorization"));
        assertFalse(persisted.contains("Basic "));
    }

    @Test
    void basicPasswordIsRequiredAtRuntimeAndNeverPartOfProfile() throws Exception {
        BtqNodeProfile profile = new BtqNodeProfile(
                URI.create("https://node.example/"),
                "qparrow",
                BtqNetwork.MAINNET,
                BtqAuthMode.BASIC,
                "rpcuser",
                null,
                Duration.ofSeconds(30));
        BtqNodeProfileStore store = new BtqNodeProfileStore(directory);

        assertThrows(IllegalArgumentException.class, () -> profile.toConfig(new char[0]));
        store.save(profile);

        String persisted = Files.readString(store.file());
        assertTrue(persisted.contains("rpcuser"));
        assertFalse(persisted.contains("rpc.password"));
        assertFalse(persisted.contains("authorization"));
    }

    @Test
    void refusesLegacyOrInjectedCredentialProperties() throws Exception {
        BtqNodeProfileStore store = new BtqNodeProfileStore(directory);
        Files.writeString(store.file(), "rpc.uri=http://127.0.0.1:18443/\nwallet.name=q\nnetwork=REGTEST\nauth.mode=NONE\nRPC.PASSWORD=do-not-load\n");

        assertThrows(Exception.class, store::load);
    }
}
