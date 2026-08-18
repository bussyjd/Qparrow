// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/** Supplies an RPC Authorization header without exposing credentials through configuration logging. */
@FunctionalInterface
public interface BtqRpcCredentials {
    String authorizationHeader() throws IOException;

    static BtqRpcCredentials none() {
        return () -> null;
    }

    static BtqRpcCredentials cookie(Path cookieFile) {
        Objects.requireNonNull(cookieFile, "cookieFile");
        return () -> {
            if(!Files.isRegularFile(cookieFile)) {
                throw new IOException("BTQ Core cookie file does not exist: " + cookieFile);
            }

            String cookie = Files.readString(cookieFile, StandardCharsets.UTF_8).trim();
            if(cookie.isEmpty() || !cookie.contains(":")) {
                throw new IOException("BTQ Core cookie file is empty or malformed: " + cookieFile);
            }
            return basicHeader(cookie);
        };
    }

    static BtqRpcCredentials basic(String username, char[] password) {
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(password, "password");
        char[] passwordCopy = password.clone();
        return () -> {
            char[] userPass = new char[username.length() + 1 + passwordCopy.length];
            username.getChars(0, username.length(), userPass, 0);
            userPass[username.length()] = ':';
            System.arraycopy(passwordCopy, 0, userPass, username.length() + 1, passwordCopy.length);
            try {
                return basicHeader(new String(userPass));
            } finally {
                Arrays.fill(userPass, '\0');
            }
        };
    }

    private static String basicHeader(String userPass) {
        return "Basic " + Base64.getEncoder().encodeToString(userPass.getBytes(StandardCharsets.UTF_8));
    }
}
