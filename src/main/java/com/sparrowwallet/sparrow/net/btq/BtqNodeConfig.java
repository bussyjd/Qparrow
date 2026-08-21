package com.sparrowwallet.sparrow.net.btq;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Objects;
import java.util.regex.Pattern;

/** Immutable connection settings for one BTQ Core wallet. */
public final class BtqNodeConfig implements AutoCloseable {
    private static final Pattern SAFE_WALLET_NAME = Pattern.compile("[A-Za-z0-9._-]{1,128}");

    private final URI rpcUri;
    private final String walletName;
    private final BtqNetwork network;
    private final BtqRpcCredentials credentials;
    private final Duration requestTimeout;

    public BtqNodeConfig(URI rpcUri, String walletName, BtqNetwork network, BtqRpcCredentials credentials, Duration requestTimeout) {
        this.rpcUri = validateRpcUri(Objects.requireNonNull(rpcUri, "rpcUri"));
        this.walletName = validateWalletName(walletName);
        this.network = Objects.requireNonNull(network, "network");
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        if(requestTimeout.isZero() || requestTimeout.isNegative()) {
            throw new IllegalArgumentException("requestTimeout must be positive");
        }
    }


    public URI rpcUri() {
        return rpcUri;
    }

    public String walletName() {
        return walletName;
    }

    public BtqNetwork network() {
        return network;
    }

    public BtqRpcCredentials credentials() {
        return credentials;
    }

    public Duration requestTimeout() {
        return requestTimeout;
    }

    public URI nodeEndpoint() {
        return rpcUri.resolve("/");
    }

    public URI walletEndpoint() {
        return rpcUri.resolve("/wallet/" + walletName);
    }


    @Override
    public void close() {
        credentials.close();
    }

    @Override
    public String toString() {
        return "BtqNodeConfig{" + rpcUri + ", wallet='" + walletName + "', network=" + network + "}";
    }

    private static String validateWalletName(String walletName) {
        Objects.requireNonNull(walletName, "walletName");
        if(!SAFE_WALLET_NAME.matcher(walletName).matches()) {
            throw new IllegalArgumentException("BTQ wallet name must contain only letters, digits, '.', '_' or '-'");
        }
        return walletName;
    }

    private static URI validateRpcUri(URI rpcUri) {
        if(rpcUri.getUserInfo() != null) {
            throw new IllegalArgumentException("Do not embed BTQ RPC credentials in the URI");
        }
        if(rpcUri.getQuery() != null || rpcUri.getFragment() != null) {
            throw new IllegalArgumentException("BTQ RPC URI must not contain a query or fragment");
        }
        if(rpcUri.getPath() != null && !rpcUri.getPath().isEmpty() && !"/".equals(rpcUri.getPath())) {
            throw new IllegalArgumentException("BTQ RPC URI path must be root '/'");
        }

        String scheme = rpcUri.getScheme();
        if(!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("BTQ RPC URI must use HTTP or HTTPS");
        }
        if(rpcUri.getHost() == null) {
            throw new IllegalArgumentException("BTQ RPC URI must include a host");
        }
        if("http".equalsIgnoreCase(scheme) && !isLoopback(rpcUri.getHost())) {
            throw new IllegalArgumentException("Plain HTTP BTQ RPC is restricted to loopback; use HTTPS for remote nodes");
        }

        String normalized = rpcUri.toString();
        if(!normalized.endsWith("/")) {
            normalized += "/";
        }
        return URI.create(normalized);
    }

    private static boolean isLoopback(String host) {
        if("localhost".equalsIgnoreCase(host)) {
            return true;
        }
        if(host.chars().anyMatch(Character::isLetter)) {
            return false;
        }
        try {
            return InetAddress.getByName(host).isLoopbackAddress();
        } catch(UnknownHostException e) {
            return false;
        }
    }
}
