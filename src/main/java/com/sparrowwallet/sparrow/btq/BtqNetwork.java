// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import java.util.Arrays;

/** Bitcoin Quantum networks supported by the node-backed wallet. */
public enum BtqNetwork {
    MAINNET("main", "qbtc", 8332),
    TESTNET("test", "tbtq", 18332),
    SIGNET("signet", "qtb", 38332),
    REGTEST("regtest", "qcrt", 18443);

    private final String rpcChain;
    private final String bech32Hrp;
    private final int rpcPort;

    BtqNetwork(String rpcChain, String bech32Hrp, int rpcPort) {
        this.rpcChain = rpcChain;
        this.bech32Hrp = bech32Hrp;
        this.rpcPort = rpcPort;
    }

    public String rpcChain() {
        return rpcChain;
    }

    public String bech32Hrp() {
        return bech32Hrp;
    }

    public int rpcPort() {
        return rpcPort;
    }

    public String p2mrPrefix() {
        return bech32Hrp + "1z";
    }

    public static BtqNetwork fromRpcChain(String chain) {
        return Arrays.stream(values())
                .filter(network -> network.rpcChain.equals(chain))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported BTQ chain: " + chain));
    }
}
