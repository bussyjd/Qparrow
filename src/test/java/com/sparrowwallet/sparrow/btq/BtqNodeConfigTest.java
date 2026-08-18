// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class BtqNodeConfigTest {
    @TempDir
    Path tempDir;

    @Test
    void buildsNetworkSpecificLocalhostConfig() {
        BtqNodeConfig config = BtqNodeConfig.localhost(BtqNetwork.REGTEST, "qparrow_test", BtqRpcCredentials.none());

        assertEquals(URI.create("http://127.0.0.1:18443/"), config.nodeEndpoint());
        assertEquals(URI.create("http://127.0.0.1:18443/wallet/qparrow_test"), config.walletEndpoint());
        assertEquals(BtqNetwork.REGTEST, config.network());
        assertFalse(config.toString().contains("password"));
    }

    @Test
    void refusesCredentialBearingAndRemotePlainHttpUris() {
        assertThrows(IllegalArgumentException.class, () -> config("http://user:pass@127.0.0.1:18443/", "wallet"));
        assertThrows(IllegalArgumentException.class, () -> config("http://example.com:18443/", "wallet"));
        assertDoesNotThrow(() -> config("https://example.com:18443/", "wallet"));
        assertThrows(IllegalArgumentException.class, () -> config("http://loopback.example:18443/", "wallet"));
        assertThrows(IllegalArgumentException.class, () -> config("http://127.0.0.1:18443/rpc", "wallet"));
    }

    @Test
    void refusesWalletNamesThatCouldAlterRpcPaths() {
        assertThrows(IllegalArgumentException.class, () -> config("http://127.0.0.1:18443/", "../wallet"));
        assertThrows(IllegalArgumentException.class, () -> config("http://127.0.0.1:18443/", "wallet name"));
        assertThrows(IllegalArgumentException.class, () -> config("http://127.0.0.1:18443/", ""));
    }

    @Test
    void cookieCredentialsAreReadOnEachRequest() throws Exception {
        Path cookie = tempDir.resolve(".cookie");
        Files.writeString(cookie, "user:first");
        BtqRpcCredentials credentials = BtqRpcCredentials.cookie(cookie);
        String first = credentials.authorizationHeader();

        Files.writeString(cookie, "user:second");
        String second = credentials.authorizationHeader();

        assertTrue(first.startsWith("Basic "));
        assertTrue(second.startsWith("Basic "));
        assertNotEquals(first, second);
        assertFalse(first.contains("first"));
        assertFalse(second.contains("second"));
    }

    @Test
    void malformedCookieFailsClosed() throws Exception {
        Path cookie = tempDir.resolve(".cookie");
        Files.writeString(cookie, "not-a-cookie");
        assertThrows(Exception.class, () -> BtqRpcCredentials.cookie(cookie).authorizationHeader());
    }

    @Test
    void rpcClientRejectsMismatchedResponseIdsAndWrongResultTypes() {
        BtqNodeConfig config = config("http://127.0.0.1:18443/", "wallet");
        BtqRpcTransport mismatched = (endpoint, authorization, timeout, request) -> {
            com.google.gson.JsonObject response = new com.google.gson.JsonObject();
            response.addProperty("id", request.get("id").getAsLong() + 1);
            response.addProperty("result", "value");
            response.add("error", com.google.gson.JsonNull.INSTANCE);
            return response;
        };
        assertThrows(BtqRpcException.class, () -> new BtqRpcClient(config, mismatched).callString("test"));

        BtqRpcTransport numericString = (endpoint, authorization, timeout, request) -> {
            com.google.gson.JsonObject response = new com.google.gson.JsonObject();
            response.add("id", request.get("id"));
            response.addProperty("result", 42);
            response.add("error", com.google.gson.JsonNull.INSTANCE);
            return response;
        };
        assertThrows(BtqRpcException.class, () -> new BtqRpcClient(config, numericString).callString("test"));
    }

    private static BtqNodeConfig config(String uri, String walletName) {
        return new BtqNodeConfig(URI.create(uri), walletName, BtqNetwork.REGTEST, BtqRpcCredentials.none(), Duration.ofSeconds(5));
    }
}
