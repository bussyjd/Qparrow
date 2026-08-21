package com.sparrowwallet.sparrow.net.btq;

import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.sparrow.io.Config;
import com.sparrowwallet.sparrow.io.Server;
import com.sparrowwallet.sparrow.net.CoreAuthType;

import java.io.File;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Builds the BTQ Core boundary from Sparrow's {@link Config} for the current network. Mirrors the
 * Bitcoin Core connection surface: a server URL plus either cookie authentication (auto-discovered
 * from the BTQ data directory) or user:pass.
 */
public final class BtqConnection {
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private BtqConnection() {
    }

    /** The chain subdirectory of a BTQ data directory holding the RPC cookie (BTQ Core layout). */
    public static String cookieSubDir(BtqNetwork network) {
        return switch(network) {
            case MAINNET -> "";
            case TESTNET -> "test";
            case SIGNET -> "signet";
            case REGTEST -> "regtest";
        };
    }

    public static Path cookieFile(File dataDir, BtqNetwork network) {
        String subDir = cookieSubDir(network);
        Path base = dataDir.toPath();
        return (subDir.isEmpty() ? base : base.resolve(subDir)).resolve(".cookie");
    }

    /** Build the node configuration from Sparrow's config for the given network. */
    public static BtqNodeConfig fromConfig(Config config, Network network) {
        Server server = config.getBtqCoreServer();
        if(server == null) {
            throw new IllegalStateException("No BTQ Core server configured");
        }
        BtqNetwork btqNetwork = BtqNetwork.fromNetwork(network);

        BtqRpcCredentials credentials;
        CoreAuthType authType = config.getBtqCoreAuthType() == null ? CoreAuthType.COOKIE : config.getBtqCoreAuthType();
        if(authType == CoreAuthType.COOKIE) {
            File dataDir = config.getBtqCoreDataDir();
            if(dataDir == null) {
                throw new IllegalStateException("No BTQ Core data directory configured for cookie authentication");
            }
            credentials = BtqRpcCredentials.cookie(cookieFile(dataDir, btqNetwork));
        } else {
            String auth = config.getBtqCoreAuth();
            if(auth == null || !auth.contains(":")) {
                throw new IllegalStateException("BTQ Core user:pass authentication is not configured");
            }
            int separator = auth.indexOf(':');
            credentials = BtqRpcCredentials.basic(auth.substring(0, separator), auth.substring(separator + 1).toCharArray());
        }

        return new BtqNodeConfig(URI.create(server.getUrl()), config.getBtqCoreWallet(), btqNetwork, credentials, DEFAULT_TIMEOUT);
    }

    /** Open the watch-only Core boundary for the current configuration and network. */
    public static BtqWatchOnlyCore openWatchOnlyCore(Config config, Network network) {
        return new BtqWatchOnlyCore(fromConfig(config, network));
    }
}
