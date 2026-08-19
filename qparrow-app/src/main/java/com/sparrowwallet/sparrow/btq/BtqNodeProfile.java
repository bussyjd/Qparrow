// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

/**
 * Persistable public connection metadata. RPC passwords and Qparrow custody
 * secrets are intentionally absent; this record is not wallet data.
 */
public record BtqNodeProfile(
        URI rpcUri,
        String walletName,
        BtqNetwork network,
        BtqAuthMode authMode,
        String rpcUsername,
        Path cookieFile,
        Duration requestTimeout
) {
    public BtqNodeProfile {
        Objects.requireNonNull(rpcUri, "rpcUri");
        Objects.requireNonNull(walletName, "walletName");
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(authMode, "authMode");
        Objects.requireNonNull(requestTimeout, "requestTimeout");
        rpcUsername = rpcUsername == null ? "" : rpcUsername;
        if(authMode == BtqAuthMode.COOKIE && cookieFile == null) {
            throw new IllegalArgumentException("A BTQ Core cookie file is required for cookie authentication");
        }
        if(authMode == BtqAuthMode.BASIC && rpcUsername.isBlank()) {
            throw new IllegalArgumentException("A BTQ RPC username is required for basic authentication");
        }
    }

    public BtqNodeConfig toConfig(char[] rpcPassword) {
        BtqRpcCredentials credentials = switch(authMode) {
            case COOKIE -> BtqRpcCredentials.cookie(cookieFile);
            case BASIC -> {
                if(rpcPassword == null || rpcPassword.length == 0) {
                    throw new IllegalArgumentException("BTQ RPC password is required and is never stored by Qparrow");
                }
                yield BtqRpcCredentials.basic(rpcUsername, rpcPassword);
            }
            case NONE -> BtqRpcCredentials.none();
        };
        return new BtqNodeConfig(rpcUri, walletName, network, credentials, requestTimeout);
    }
}
