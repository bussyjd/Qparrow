// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sparrowwallet.sparrow.btq.BtqNetwork;
import com.sparrowwallet.sparrow.btq.BtqNodeConfig;
import com.sparrowwallet.sparrow.btq.BtqP2mrAddressCodec;
import com.sparrowwallet.sparrow.btq.BtqRpcClient;

import java.util.HexFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/** Public-only BTQ Core boundary for a Qparrow-custody wallet. */
public final class BtqWatchOnlyCore {
    /** 41-byte base input at 16x plus the maximum single-key P2MR witness. */
    public static final int SINGLE_KEY_P2MR_INPUT_WEIGHT = 4402;
    private static final long MAX_MONEY_SATS = 21_000_000L * 100_000_000L;
    private static final Pattern P2MR_ID = Pattern.compile("[0-9a-fA-F]{16}");
    private static final HexFormat HEX = HexFormat.of();

    private final BtqNodeConfig config;
    private final BtqRpcClient nodeRpc;
    private final BtqRpcClient walletRpc;

    public BtqWatchOnlyCore(BtqNodeConfig config) {
        this(config, new BtqRpcClient(config));
    }

    public BtqWatchOnlyCore(BtqNodeConfig config, BtqRpcClient rpcClient) {
        this.config = Objects.requireNonNull(config, "config");
        this.nodeRpc = Objects.requireNonNull(rpcClient, "rpcClient").node();
        this.walletRpc = rpcClient.wallet();
    }

    /** Prove that the configured endpoint is the expected BTQ chain before touching wallet state. */
    public NodeStatus verifyNode() {
        JsonObject networkInfo = nodeRpc.callObject("getnetworkinfo");
        JsonObject blockchainInfo = nodeRpc.callObject("getblockchaininfo");
        String subversion = requiredString(networkInfo, "subversion", "getnetworkinfo");
        BtqNetwork reportedNetwork;
        try {
            reportedNetwork = BtqNetwork.fromRpcChain(requiredString(blockchainInfo, "chain", "getblockchaininfo"));
        } catch(IllegalArgumentException e) {
            throw new IllegalStateException("BTQ Core returned an unsupported chain", e);
        }
        if(reportedNetwork != config.network()) {
            throw new IllegalStateException("BTQ Core chain does not match the selected Qparrow network");
        }
        if(!subversion.toLowerCase(java.util.Locale.ROOT).contains("btq")) {
            throw new IllegalStateException("RPC endpoint does not identify as BTQ Core");
        }
        int blocks = requiredInt(blockchainInfo, "blocks", "getblockchaininfo");
        int headers = requiredInt(blockchainInfo, "headers", "getblockchaininfo");
        if(blocks < 0 || headers < blocks) {
            throw new IllegalStateException("BTQ Core returned invalid synchronization heights");
        }
        return new NodeStatus(subversion, reportedNetwork, blocks, headers,
                optionalBoolean(blockchainInfo, "initialblockdownload", true));
    }

    /** Create or load a descriptor wallet that is structurally unable to hold private keys. */
    public WalletStatus ensureWallet() {
        boolean loaded = false;
        for(JsonElement element : nodeRpc.callArray("listwallets")) {
            if(config.walletName().equals(element.getAsString())) {
                loaded = true;
                break;
            }
        }

        if(!loaded) {
            boolean exists = false;
            JsonObject walletDirectory = nodeRpc.callObject("listwalletdir");
            JsonArray wallets = walletDirectory.getAsJsonArray("wallets");
            if(wallets != null) {
                for(JsonElement element : wallets) {
                    JsonObject wallet = element.getAsJsonObject();
                    if(config.walletName().equals(requiredString(wallet, "name", "listwalletdir"))) {
                        exists = true;
                        break;
                    }
                }
            }
            if(exists) {
                nodeRpc.call("loadwallet", config.walletName(), true);
            } else {
                // disable_private_keys=true, blank=true, descriptors=true.
                nodeRpc.call("createwallet", config.walletName(), true, true, "", false, true, true, false);
            }
        }

        JsonObject info = walletRpc.callObject("getwalletinfo");
        WalletStatus status = new WalletStatus(
                requiredString(info, "walletname", "getwalletinfo"),
                optionalBoolean(info, "descriptors", false),
                optionalBoolean(info, "private_keys_enabled", true),
                optionalBoolean(info, "blank", false));
        if(!config.walletName().equals(status.name())) {
            throw new IllegalStateException("BTQ Core returned an unexpected wallet");
        }
        if(!status.descriptors() || status.privateKeysEnabled() || !status.blank()) {
            throw new IllegalStateException("Qparrow custody requires a blank descriptor wallet with private keys disabled");
        }
        return status;
    }

    /** Register exactly one Qparrow-derived P2MR leaf as Core watch-only metadata. */
    public RegisteredAddress registerAddress(BtqP2mrKeyPath.Address localAddress, String label) {
        return registerAddress(localAddress, label, "now");
    }

    /** Recovery registration uses genesis so Core can rediscover historical transactions. */
    public RegisteredAddress registerHistoricalAddress(BtqP2mrKeyPath.Address localAddress, String label) {
        return registerAddress(localAddress, label, 0);
    }

    private RegisteredAddress registerAddress(BtqP2mrKeyPath.Address localAddress, String label,
                                                Object timestamp) {
        Objects.requireNonNull(localAddress, "localAddress");
        JsonObject walletInfo = walletRpc.callObject("getwalletinfo");
        if(optionalBoolean(walletInfo, "private_keys_enabled", true)
                || !optionalBoolean(walletInfo, "descriptors", false)) {
            throw new IllegalStateException("refusing to register custody metadata in a wallet that can hold private keys");
        }
        if(localAddress.network() != config.network()) {
            throw new IllegalArgumentException("address network does not match the BTQ Core connection");
        }
        if(!BtqP2mrAddressCodec.isCanonicalAddress(config.network(), localAddress.address())) {
            throw new IllegalArgumentException("local address is not canonical P2MR");
        }

        JsonObject leaf = new JsonObject();
        leaf.addProperty("depth", 0);
        leaf.addProperty("leaf_version", BtqP2mrKeyPath.LEAF_VERSION);
        leaf.addProperty("script", HEX.formatHex(localAddress.leafScript()));
        JsonArray tree = new JsonArray();
        tree.add(leaf);
        JsonObject created = walletRpc.callObject("getnewp2mraddress", tree, label == null ? "" : label);

        RegisteredAddress registered = new RegisteredAddress(
                requiredString(created, "p2mr_id", "getnewp2mraddress"),
                requiredString(created, "address", "getnewp2mraddress"),
                requiredString(created, "scriptPubKey", "getnewp2mraddress"),
                requiredString(created, "merkle_root", "getnewp2mraddress"));
        if(!P2MR_ID.matcher(registered.p2mrId()).matches()) {
            throw new IllegalStateException("BTQ Core returned an invalid P2MR metadata id");
        }
        String localScript = HEX.formatHex(localAddress.scriptPubKey());
        String localRoot = HEX.formatHex(localAddress.merkleRoot());
        if(!localAddress.address().equals(registered.address())
                || !localScript.equalsIgnoreCase(registered.scriptPubKey())
                || !localRoot.equalsIgnoreCase(registered.merkleRoot())) {
            throw new IllegalStateException("BTQ Core did not register the exact Qparrow P2MR commitment");
        }

        // P2MR metadata supplies the tree, but it is not descriptor-backed and
        // by itself does not set the birth time of a blank watch-only wallet.
        // Pair it with Core's standard addr() descriptor so block scanning,
        // restart persistence, and upstream wallet progress remain inherited.
        JsonObject descriptorInfo = nodeRpc.callObject("getdescriptorinfo", "addr(" + registered.address() + ")");
        String descriptor = requiredString(descriptorInfo, "descriptor", "getdescriptorinfo");
        if(!descriptor.startsWith("addr(" + registered.address() + ")#")
                || optionalBoolean(descriptorInfo, "isrange", true)
                || optionalBoolean(descriptorInfo, "issolvable", true)
                || optionalBoolean(descriptorInfo, "hasprivatekeys", true)) {
            throw new IllegalStateException("BTQ Core returned an unsafe watch descriptor");
        }
        JsonObject descriptorImport = new JsonObject();
        descriptorImport.addProperty("desc", descriptor);
        if(timestamp instanceof String text) {
            descriptorImport.addProperty("timestamp", text);
        } else if(timestamp instanceof Number number) {
            descriptorImport.addProperty("timestamp", number);
        } else {
            throw new IllegalArgumentException("invalid descriptor timestamp");
        }
        descriptorImport.addProperty("active", false);
        descriptorImport.addProperty("internal", localAddress.chain() == BtqCustodySpec.Chain.CHANGE);
        if(localAddress.chain() == BtqCustodySpec.Chain.RECEIVE) {
            descriptorImport.addProperty("label", label == null ? "" : label);
        }
        JsonArray imports = new JsonArray();
        imports.add(descriptorImport);
        JsonArray imported = walletRpc.callArray("importdescriptors", imports);
        if(imported.size() != 1 || !optionalBoolean(imported.get(0).getAsJsonObject(), "success", false)) {
            throw new IllegalStateException("BTQ Core did not import the Qparrow watch descriptor");
        }

        JsonObject info = walletRpc.callObject("getaddressinfo", registered.address());
        // DescriptorScriptPubKeyMan reports imported addr() descriptors as
        // ismine=true even in a private-key-disabled wallet. The wallet flag
        // checked above is the custody invariant; iswatchonly is not.
        if(!optionalBoolean(info, "ismine", false)
                || !optionalBoolean(info, "solvable", false)
                || !optionalBoolean(info, "isdilithium", false)
                || optionalInt(info, "witness_version", -1) != 2
                || !localScript.equalsIgnoreCase(requiredString(info, "scriptPubKey", "getaddressinfo"))) {
            throw new IllegalStateException("BTQ Core did not classify the Qparrow address as watch-only P2MR");
        }
        return registered;
    }

    public RescanResult rescanFromGenesis() {
        requirePrivateKeysDisabled();
        JsonObject result = walletRpc.callObject("rescanblockchain", 0);
        int start = requiredInt(result, "start_height", "rescanblockchain");
        int stop = requiredInt(result, "stop_height", "rescanblockchain");
        if(start != 0 || stop < start) {
            throw new IllegalStateException("BTQ Core returned invalid rescan heights");
        }
        return new RescanResult(start, stop);
    }

    public List<WatchedUtxo> listUtxos(int minimumConfirmations) {
        if(minimumConfirmations < 0) {
            throw new IllegalArgumentException("minimum confirmations cannot be negative");
        }
        requirePrivateKeysDisabled();
        JsonArray unspent = walletRpc.callArray("listunspent", minimumConfirmations, 9999999,
                new JsonArray(), false);
        List<WatchedUtxo> validated = new ArrayList<>(unspent.size());
        Set<String> outpoints = new HashSet<>();
        for(JsonElement element : unspent) {
            if(!element.isJsonObject()) {
                throw new IllegalStateException("BTQ Core returned a non-object UTXO");
            }
            JsonObject utxo = element.getAsJsonObject();
            String txid = requiredString(utxo, "txid", "listunspent");
            int vout = requiredInt(utxo, "vout", "listunspent");
            String address = requiredString(utxo, "address", "listunspent");
            String script = requiredString(utxo, "scriptPubKey", "listunspent");
            int confirmations = requiredInt(utxo, "confirmations", "listunspent");
            if(!txid.matches("[0-9a-fA-F]{64}") || vout < 0 || confirmations < minimumConfirmations) {
                throw new IllegalStateException("BTQ Core returned invalid UTXO identity or confirmation data");
            }
            if(!outpoints.add(txid.toLowerCase(java.util.Locale.ROOT) + ':' + vout)) {
                throw new IllegalStateException("BTQ Core returned a duplicate UTXO");
            }
            if(!BtqP2mrAddressCodec.isCanonicalAddress(config.network(), address)) {
                throw new IllegalStateException("BTQ Core returned a non-P2MR or wrong-network UTXO");
            }
            String expectedScript = HEX.formatHex(BtqP2mrAddressCodec.scriptPubKey(config.network(), address));
            if(!expectedScript.equalsIgnoreCase(script)) {
                throw new IllegalStateException("BTQ Core returned an address/script mismatch");
            }
            long amountSats;
            try {
                amountSats = utxo.get("amount").getAsBigDecimal().movePointRight(8).longValueExact();
            } catch(Exception e) {
                throw new IllegalStateException("BTQ Core returned an invalid UTXO amount", e);
            }
            if(amountSats <= 0 || amountSats > MAX_MONEY_SATS) {
                throw new IllegalStateException("BTQ Core returned an out-of-range UTXO amount");
            }
            validated.add(new WatchedUtxo(txid, vout, address, script.toLowerCase(java.util.Locale.ROOT),
                    amountSats, confirmations));
        }
        return List.copyOf(validated);
    }

    /**
     * Ask Core to construct, but never sign, an explicit-input P2MR PSBT.
     * Coin selection and change derivation remain Qparrow-owned.
     */
    public FundedPsbt createFundedPsbt(List<Outpoint> selectedInputs, List<Payment> payments,
                                       BtqP2mrKeyPath.Address changeAddress, long feeRateSatsPerVbyte) {
        Objects.requireNonNull(selectedInputs, "selectedInputs");
        Objects.requireNonNull(payments, "payments");
        Objects.requireNonNull(changeAddress, "changeAddress");
        requirePrivateKeysDisabled();
        if(selectedInputs.isEmpty() || selectedInputs.size() > BtqPsbtSigner.MAX_SIGNING_INPUTS) {
            throw new IllegalArgumentException("explicit input count is outside the Qparrow signing limit");
        }
        if(payments.isEmpty() || payments.size() > BtqPsbtSigner.MAX_OUTPUTS - 1) {
            throw new IllegalArgumentException("payment count is outside the Qparrow signing limit");
        }
        if(changeAddress.network() != config.network()
                || changeAddress.chain() != BtqCustodySpec.Chain.CHANGE
                || !BtqP2mrAddressCodec.isCanonicalAddress(config.network(), changeAddress.address())) {
            throw new IllegalArgumentException("change must be a local same-network Qparrow change address");
        }
        if(feeRateSatsPerVbyte <= 0 || feeRateSatsPerVbyte > 10_000) {
            throw new IllegalArgumentException("fee rate must be between 1 and 10000 sat/vB");
        }

        JsonArray inputs = new JsonArray();
        Set<String> outpoints = new HashSet<>();
        for(Outpoint selectedInput : selectedInputs) {
            Objects.requireNonNull(selectedInput, "selected input");
            if(!outpoints.add(selectedInput.txid().toLowerCase(java.util.Locale.ROOT) + ':' + selectedInput.vout())) {
                throw new IllegalArgumentException("duplicate selected input");
            }
            JsonObject input = new JsonObject();
            input.addProperty("txid", selectedInput.txid());
            input.addProperty("vout", selectedInput.vout());
            input.addProperty("weight", SINGLE_KEY_P2MR_INPUT_WEIGHT);
            inputs.add(input);
        }

        JsonArray outputs = new JsonArray();
        Set<String> outputAddresses = new HashSet<>();
        for(Payment payment : payments) {
            Objects.requireNonNull(payment, "payment");
            if(!BtqP2mrAddressCodec.isCanonicalAddress(config.network(), payment.address())) {
                throw new IllegalArgumentException("payment address is not same-network P2MR");
            }
            if(!outputAddresses.add(payment.address()) || payment.address().equals(changeAddress.address())) {
                throw new IllegalArgumentException("payment and change addresses must be distinct");
            }
            JsonObject output = new JsonObject();
            output.addProperty(payment.address(), java.math.BigDecimal.valueOf(payment.amountSats(), 8));
            outputs.add(output);
        }

        JsonObject options = new JsonObject();
        options.addProperty("add_inputs", false);
        options.addProperty("include_watching", true);
        options.addProperty("change_address", changeAddress.address());
        options.addProperty("fee_rate", feeRateSatsPerVbyte);
        JsonObject funded = walletRpc.callObject("walletcreatefundedpsbt", inputs, outputs, 0, options, false);
        String psbt = requiredString(funded, "psbt", "walletcreatefundedpsbt");
        if(psbt.isBlank()) throw new IllegalStateException("BTQ Core returned an empty PSBT");
        long feeSats;
        try {
            feeSats = funded.get("fee").getAsBigDecimal().movePointRight(8).longValueExact();
        } catch(Exception e) {
            throw new IllegalStateException("BTQ Core returned an invalid funding fee", e);
        }
        int changePosition = optionalInt(funded, "changepos", -1);
        if(feeSats < 0 || changePosition < -1 || changePosition >= payments.size() + 1) {
            throw new IllegalStateException("BTQ Core returned invalid funding metadata");
        }
        return new FundedPsbt(psbt, feeSats, changePosition);
    }

    /** Finalize only a PSBT already validated and signed by {@link BtqPsbtSigner}. */
    public FinalizedTransaction finalizePsbt(BtqPsbtSigner.SignedPsbt signedPsbt) {
        Objects.requireNonNull(signedPsbt, "signedPsbt");
        JsonObject finalized = nodeRpc.callObject("finalizepsbt", signedPsbt.base64(), true);
        if(!optionalBoolean(finalized, "complete", false)) {
            throw new IllegalStateException("BTQ Core could not finalize the Qparrow P2MR signature");
        }
        String hex = requiredString(finalized, "hex", "finalizepsbt");
        final String localTxid;
        try {
            localTxid = BtqPsbtSigner.finalizedTransactionId(hex);
        } catch(IllegalArgumentException e) {
            throw new IllegalStateException("BTQ Core returned invalid finalized transaction hex", e);
        }
        if(!localTxid.equals(signedPsbt.expectedTxid())) {
            throw new IllegalStateException("BTQ Core finalized a transaction other than the locally signed proposal");
        }
        JsonArray acceptance = nodeRpc.callArray("testmempoolaccept", List.of(hex));
        if(acceptance.size() != 1) {
            throw new IllegalStateException("BTQ Core returned invalid mempool acceptance data");
        }
        JsonObject result = acceptance.get(0).getAsJsonObject();
        if(!optionalBoolean(result, "allowed", false)) {
            String reason = result.has("reject-reason") ? result.get("reject-reason").getAsString() : "rejected";
            throw new IllegalStateException("BTQ Core rejected the signed custody transaction: " + reason);
        }
        String txid = requiredString(result, "txid", "testmempoolaccept");
        if(!txid.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalStateException("BTQ Core returned an invalid transaction id");
        }
        if(!txid.equalsIgnoreCase(localTxid)) {
            throw new IllegalStateException("BTQ Core returned a transaction id inconsistent with finalized bytes");
        }
        return new FinalizedTransaction(hex, localTxid);
    }

    /** Broadcast only a transaction already finalized and dry-run by this boundary. */
    public BroadcastResult broadcast(FinalizedTransaction transaction) {
        Objects.requireNonNull(transaction, "transaction");
        String broadcastTxid = nodeRpc.callString("sendrawtransaction", transaction.hex());
        if(!broadcastTxid.matches("[0-9a-fA-F]{64}")
                || !broadcastTxid.equalsIgnoreCase(transaction.txid())) {
            throw new IllegalStateException("BTQ Core returned an unexpected broadcast transaction id");
        }
        return new BroadcastResult(broadcastTxid.toLowerCase(java.util.Locale.ROOT));
    }

    private void requirePrivateKeysDisabled() {
        JsonObject info = walletRpc.callObject("getwalletinfo");
        if(optionalBoolean(info, "private_keys_enabled", true)
                || !optionalBoolean(info, "descriptors", false)) {
            throw new IllegalStateException("Qparrow custody requires a private-key-disabled descriptor wallet");
        }
    }

    private static String requiredString(JsonObject object, String field, String method) {
        if(!object.has(field) || object.get(field).isJsonNull() || !object.get(field).isJsonPrimitive()) {
            throw new IllegalStateException(method + " did not return " + field);
        }
        return object.get(field).getAsString();
    }

    private static boolean optionalBoolean(JsonObject object, String field, boolean fallback) {
        return object.has(field) && !object.get(field).isJsonNull() ? object.get(field).getAsBoolean() : fallback;
    }

    private static int optionalInt(JsonObject object, String field, int fallback) {
        return object.has(field) && !object.get(field).isJsonNull() ? object.get(field).getAsInt() : fallback;
    }

    private static int requiredInt(JsonObject object, String field, String method) {
        if(!object.has(field) || object.get(field).isJsonNull() || !object.get(field).isJsonPrimitive()) {
            throw new IllegalStateException(method + " did not return " + field);
        }
        try {
            return object.get(field).getAsInt();
        } catch(RuntimeException e) {
            throw new IllegalStateException(method + " returned invalid " + field, e);
        }
    }

    public record NodeStatus(String subversion, BtqNetwork network, int blocks, int headers,
                             boolean initialBlockDownload) {
    }

    public record WalletStatus(String name, boolean descriptors, boolean privateKeysEnabled, boolean blank) {
    }

    public record RegisteredAddress(String p2mrId, String address, String scriptPubKey, String merkleRoot) {
    }

    public record RescanResult(int startHeight, int stopHeight) {
    }

    public record WatchedUtxo(String txid, int vout, String address, String scriptPubKey,
                              long amountSats, int confirmations) {
    }

    public record Outpoint(String txid, int vout) {
        public Outpoint {
            if(txid == null || !txid.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalArgumentException("transaction id must be 32-byte hexadecimal");
            }
            if(vout < 0) throw new IllegalArgumentException("output index cannot be negative");
        }
    }

    public record Payment(String address, long amountSats) {
        public Payment {
            if(address == null || address.isBlank()) throw new IllegalArgumentException("payment address is required");
            if(amountSats <= 0 || amountSats > MAX_MONEY_SATS) {
                throw new IllegalArgumentException("payment amount is outside the monetary range");
            }
        }
    }

    public record FundedPsbt(String base64, long feeSats, int changePosition) {
    }

    public record FinalizedTransaction(String hex, String txid) {
    }

    public record BroadcastResult(String txid) {
    }
}
