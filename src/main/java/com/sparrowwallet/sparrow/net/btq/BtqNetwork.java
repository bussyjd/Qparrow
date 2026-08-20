// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.net.btq;

import java.util.Arrays;

/** Bitcoin Quantum networks supported by the node-backed wallet. */
public enum BtqNetwork {
    MAINNET("main", "qbtc", 8332, "000003194a90d8d8eff8b39a7ad4e2490729b97a6772b7f4c4cb8887dffd1ae4", null),
    TESTNET("test", "tbtq", 18332, "000000ffba1eed17608850f753ca60e74456dd3fe7af86b72aadba7d6052f7dd", null),
    SIGNET("signet", "qtb", 38332, "00000120a12ac337785653cdff1f23b4891d3ffeb492a011cc95b165e86a4b15",
            "522103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"),
    REGTEST("regtest", "qcrt", 18443, "5a6c309a7e9bb2fa314e63630520ca3c598c86a91dd2c6737e160cfadfc50f38", null);

    private final String rpcChain;
    private final String bech32Hrp;
    private final int rpcPort;
    private final String genesisHash;
    private final String signetChallenge;

    BtqNetwork(String rpcChain, String bech32Hrp, int rpcPort, String genesisHash, String signetChallenge) {
        this.rpcChain = rpcChain;
        this.bech32Hrp = bech32Hrp;
        this.rpcPort = rpcPort;
        this.genesisHash = genesisHash;
        this.signetChallenge = signetChallenge;
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

    public String genesisHash() {
        return genesisHash;
    }

    public String signetChallenge() {
        return signetChallenge;
    }

    public String p2mrPrefix() {
        return bech32Hrp + "1z";
    }

    /** The BTQ network for a drongo network: the two enums are deliberately kept aligned by rpc chain name. */
    public static BtqNetwork fromNetwork(com.sparrowwallet.drongo.Network network) {
        return switch(network) {
            case MAINNET -> MAINNET;
            case TESTNET, TESTNET4 -> TESTNET;
            case SIGNET -> SIGNET;
            case REGTEST -> REGTEST;
        };
    }

    /** The drongo network for this BTQ network, for address encoding and derivation. */
    public com.sparrowwallet.drongo.Network toNetwork() {
        return switch(this) {
            case MAINNET -> com.sparrowwallet.drongo.Network.MAINNET;
            case TESTNET -> com.sparrowwallet.drongo.Network.TESTNET;
            case SIGNET -> com.sparrowwallet.drongo.Network.SIGNET;
            case REGTEST -> com.sparrowwallet.drongo.Network.REGTEST;
        };
    }

    public static BtqNetwork fromRpcChain(String chain) {
        return Arrays.stream(values())
                .filter(network -> network.rpcChain.equals(chain))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported BTQ chain: " + chain));
    }
}
