package com.sparrowwallet.sparrow.net.btq;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.address.Address;
import com.sparrowwallet.drongo.address.InvalidAddressException;
import com.sparrowwallet.drongo.address.P2MRAddress;
import com.sparrowwallet.drongo.btq.P2MR;
import com.sparrowwallet.drongo.protocol.Transaction;

import java.util.HexFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Public-only BTQ Core boundary for a Bitcoin Quantum custody wallet.
 * <p>
 * Adapted from the Qparrow implementation proven on BTQ public testnet: Core is verified as the
 * expected BTQ chain, holds only a blank private-key-disabled descriptor wallet, constructs (but never
 * signs) explicit-input PSBTs, and acts as the default-policy oracle and broadcaster. All key material,
 * P2MR construction and ML-DSA signing stay on the wallet side (drongo {@code btq} package).
 */
public final class BtqWatchOnlyCore implements AutoCloseable {
    /** 41-byte base input at 16x plus the maximum single-key P2MR witness. */
    public static final int SINGLE_KEY_P2MR_INPUT_WEIGHT = 4402;
    /** The custody signing limits, matching the proven Qparrow signer bounds. */
    public static final int MAX_SIGNING_INPUTS = 128;
    public static final int MAX_OUTPUTS = 128;
    /** Blocks per rescanblockchain call; bounded so each call returns well inside the RPC request timeout. */
    private static final int RESCAN_CHUNK_BLOCKS = 5000;
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
            throw new IllegalStateException("BTQ Core chain does not match the selected network");
        }
        if(!subversion.toLowerCase(java.util.Locale.ROOT).contains("btq")) {
            throw new IllegalStateException("RPC endpoint does not identify as BTQ Core");
        }
        String genesisHash = nodeRpc.callString("getblockhash", 0);
        if(!reportedNetwork.genesisHash().equalsIgnoreCase(genesisHash)) {
            throw new IllegalStateException("RPC endpoint genesis block does not match the selected BTQ network");
        }
        requireChangeRegistrationSupport();
        if(reportedNetwork == BtqNetwork.SIGNET) {
            JsonObject miningInfo = nodeRpc.callObject("getmininginfo");
            if(!miningInfo.has("signet_challenge") || miningInfo.get("signet_challenge").isJsonNull()) {
                throw new IllegalStateException("BTQ Core build lacks getmininginfo.signet_challenge"
                        + " — requires btq-core f36e0b28e or later");
            }
            String challenge = requiredString(miningInfo, "signet_challenge", "getmininginfo");
            if(!reportedNetwork.signetChallenge().equalsIgnoreCase(challenge)) {
                throw new IllegalStateException("custom BTQ signet challenges are not supported by this custody wallet");
            }
        }
        int blocks = requiredInt(blockchainInfo, "blocks", "getblockchaininfo");
        int headers = requiredInt(blockchainInfo, "headers", "getblockchaininfo");
        if(blocks < 0 || headers < blocks) {
            throw new IllegalStateException("BTQ Core returned invalid synchronization heights");
        }
        boolean pruned = optionalBoolean(blockchainInfo, "pruned", false);
        int pruneHeight = pruned ? optionalInt(blockchainInfo, "pruneheight", -1) : -1;
        if(pruned && pruneHeight < 0) {
            throw new IllegalStateException("BTQ Core returned invalid pruning state");
        }
        return new NodeStatus(subversion, reportedNetwork, genesisHash.toLowerCase(java.util.Locale.ROOT),
                blocks, headers, optionalBoolean(blockchainInfo, "initialblockdownload", true),
                pruned, pruneHeight);
    }

    /**
     * Every custody spend mints change first, and change registration needs the third
     * {@code internal} parameter of {@code getnewp2mraddress}. Older builds declare two parameters and
     * fail the first registration with the raw RPC help text, so probe the declared arity once here.
     */
    private void requireChangeRegistrationSupport() {
        final String help;
        try {
            help = nodeRpc.callString("help", "getnewp2mraddress");
        } catch(RuntimeException e) {
            throw new IllegalStateException("BTQ Core build lacks getnewp2mraddress(internal)"
                    + " — requires btq-core e3da3f784 or later", e);
        }
        if(!help.contains("internal")) {
            throw new IllegalStateException("BTQ Core build lacks getnewp2mraddress(internal)"
                    + " — requires btq-core e3da3f784 or later");
        }
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
            throw new IllegalStateException("BTQ custody requires a blank descriptor wallet with private keys disabled");
        }
        return status;
    }

    /** Register exactly one wallet-derived P2MR leaf as Core watch-only metadata. */
    public RegisteredAddress registerAddress(P2MR.P2MRScript localScript, KeyPurpose keyPurpose, String label) {
        return registerAddress(localScript, keyPurpose, label, "now");
    }

    /** Recovery registers without an implicit scan; the caller performs one explicit historical rescan. */
    public RegisteredAddress registerHistoricalAddress(P2MR.P2MRScript localScript, KeyPurpose keyPurpose, String label) {
        return registerAddress(localScript, keyPurpose, label, "now");
    }

    private RegisteredAddress registerAddress(P2MR.P2MRScript localScript, KeyPurpose keyPurpose, String label,
                                                Object timestamp) {
        Objects.requireNonNull(localScript, "localScript");
        Objects.requireNonNull(keyPurpose, "keyPurpose");
        JsonObject walletInfo = walletRpc.callObject("getwalletinfo");
        if(optionalBoolean(walletInfo, "private_keys_enabled", true)
                || !optionalBoolean(walletInfo, "descriptors", false)) {
            throw new IllegalStateException("refusing to register custody metadata in a wallet that can hold private keys");
        }
        //Re-encoding the merkle root under the connection's network proves the address network binding
        if(!new P2MRAddress(localScript.merkleRoot()).getAddress(config.network().toNetwork()).equals(localScript.address())) {
            throw new IllegalArgumentException("address network does not match the BTQ Core connection");
        }
        if(parseP2mrAddress(localScript.address()) == null) {
            throw new IllegalArgumentException("local address is not canonical P2MR");
        }

        JsonObject leaf = new JsonObject();
        leaf.addProperty("depth", 0);
        leaf.addProperty("leaf_version", P2MR.LEAF_VERSION);
        leaf.addProperty("script", HEX.formatHex(localScript.leafScript()));
        JsonArray tree = new JsonArray();
        tree.add(leaf);
        boolean internal = keyPurpose == KeyPurpose.CHANGE;
        JsonObject created = walletRpc.callObject("getnewp2mraddress", tree, label == null ? "" : label, internal);

        RegisteredAddress registered = new RegisteredAddress(
                requiredString(created, "p2mr_id", "getnewp2mraddress"),
                requiredString(created, "address", "getnewp2mraddress"),
                requiredString(created, "scriptPubKey", "getnewp2mraddress"),
                requiredString(created, "merkle_root", "getnewp2mraddress"));
        if(!P2MR_ID.matcher(registered.p2mrId()).matches()) {
            throw new IllegalStateException("BTQ Core returned an invalid P2MR metadata id");
        }
        String localScriptHex = HEX.formatHex(localScript.outputScript());
        String localRoot = HEX.formatHex(localScript.merkleRoot());
        if(!localScript.address().equals(registered.address())
                || !localScriptHex.equalsIgnoreCase(registered.scriptPubKey())
                || !localRoot.equalsIgnoreCase(registered.merkleRoot())) {
            throw new IllegalStateException("BTQ Core did not register the exact wallet P2MR commitment");
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
        descriptorImport.addProperty("internal", internal);
        if(keyPurpose == KeyPurpose.RECEIVE) {
            descriptorImport.addProperty("label", label == null ? "" : label);
        }
        JsonArray imports = new JsonArray();
        imports.add(descriptorImport);
        JsonArray imported = walletRpc.callArray("importdescriptors", imports);
        if(imported.size() != 1 || !optionalBoolean(imported.get(0).getAsJsonObject(), "success", false)) {
            throw new IllegalStateException("BTQ Core did not import the watch descriptor");
        }

        JsonObject info = walletRpc.callObject("getaddressinfo", registered.address());
        // DescriptorScriptPubKeyMan reports imported addr() descriptors as
        // ismine=true even in a private-key-disabled wallet. The wallet flag
        // checked above is the custody invariant; iswatchonly is not.
        if(!optionalBoolean(info, "ismine", false)
                || !optionalBoolean(info, "solvable", false)
                || !optionalBoolean(info, "isdilithium", false)
                || requiredBoolean(info, "ischange", "getaddressinfo") != internal
                || optionalInt(info, "witness_version", -1) != 2
                || !localScriptHex.equalsIgnoreCase(requiredString(info, "scriptPubKey", "getaddressinfo"))) {
            throw new IllegalStateException("BTQ Core did not classify the address as watch-only P2MR");
        }
        return registered;
    }

    /** Rescan the whole chain for watch-wallet history in bounded height ranges, so no single RPC call outlives the request timeout. */
    public RescanResult rescanFromGenesis() {
        requirePrivateKeysDisabled();
        int tip = requiredInt(nodeRpc.callObject("getblockchaininfo"), "blocks", "getblockchaininfo");
        int start = 0;
        while(start <= tip) {
            int stop = Math.min(start + RESCAN_CHUNK_BLOCKS - 1, tip);
            JsonObject result = null;
            for(int attempt = 0; attempt < 3; attempt++) {
                JsonObject chunk = walletRpc.callObject("rescanblockchain", start, stop);
                if(requiredInt(chunk, "start_height", "rescanblockchain") != start) {
                    throw new IllegalStateException("BTQ Core returned an invalid rescan start height");
                }
                if(chunk.has("stop_height") && !chunk.get("stop_height").isJsonNull()) {
                    result = chunk;
                    break;
                }
            }
            if(result == null) {
                throw new IllegalStateException("BTQ Core could not complete a stable rescan after three attempts");
            }
            if(requiredInt(result, "stop_height", "rescanblockchain") != stop) {
                throw new IllegalStateException("BTQ Core returned invalid rescan heights");
            }
            start = stop + 1;
        }
        return new RescanResult(0, tip);
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
            P2MRAddress parsed = parseP2mrAddress(address);
            if(parsed == null) {
                throw new IllegalStateException("BTQ Core returned a non-P2MR or wrong-network UTXO");
            }
            String expectedScript = HEX.formatHex(parsed.getOutputScript().getProgram());
            if(!expectedScript.equalsIgnoreCase(script)) {
                throw new IllegalStateException("BTQ Core returned an address/script mismatch");
            }
            long amountSats;
            try {
                amountSats = utxo.get("amount").getAsBigDecimal().movePointRight(8).longValueExact();
            } catch(Exception e) {
                throw new IllegalStateException("BTQ Core returned an invalid UTXO amount", e);
            }
            if(amountSats < 0 || amountSats > MAX_MONEY_SATS) {
                throw new IllegalStateException("BTQ Core returned an out-of-range UTXO amount");
            }
            if(amountSats == 0) continue;
            validated.add(new WatchedUtxo(txid, vout, address, script.toLowerCase(java.util.Locale.ROOT),
                    amountSats, confirmations));
        }
        return List.copyOf(validated);
    }

    /**
     * Ask Core to construct, but never sign, an explicit-input P2MR PSBT.
     * Coin selection and change derivation remain wallet-owned; the caller must pass a CHANGE-chain
     * derived script as {@code changeScript} (the boundary cannot see the derivation chain).
     */
    public FundedPsbt createFundedPsbt(List<Outpoint> selectedInputs, List<Payment> payments,
                                       P2MR.P2MRScript changeScript, long feeRateSatsPerVbyte) {
        Objects.requireNonNull(selectedInputs, "selectedInputs");
        Objects.requireNonNull(payments, "payments");
        Objects.requireNonNull(changeScript, "changeScript");
        requirePrivateKeysDisabled();
        if(selectedInputs.isEmpty() || selectedInputs.size() > MAX_SIGNING_INPUTS) {
            throw new IllegalArgumentException("explicit input count is outside the custody signing limit");
        }
        if(payments.isEmpty() || payments.size() > MAX_OUTPUTS - 1) {
            throw new IllegalArgumentException("payment count is outside the custody signing limit");
        }
        if(!new P2MRAddress(changeScript.merkleRoot()).getAddress(config.network().toNetwork()).equals(changeScript.address())
                || parseP2mrAddress(changeScript.address()) == null) {
            throw new IllegalArgumentException("change must be a local same-network P2MR address");
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
            if(parseP2mrAddress(payment.address()) == null) {
                throw new IllegalArgumentException("payment address is not same-network P2MR");
            }
            if(!outputAddresses.add(payment.address()) || payment.address().equals(changeScript.address())) {
                throw new IllegalArgumentException("payment and change addresses must be distinct");
            }
            JsonObject output = new JsonObject();
            output.addProperty(payment.address(), java.math.BigDecimal.valueOf(payment.amountSats(), 8));
            outputs.add(output);
        }

        JsonObject options = new JsonObject();
        options.addProperty("add_inputs", false);
        options.addProperty("include_watching", true);
        options.addProperty("change_address", changeScript.address());
        options.addProperty("fee_rate", feeRateSatsPerVbyte);
        // Ask for BIP125 signalling explicitly so it does not depend on the node's -walletrbf setting.
        options.addProperty("replaceable", true);
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

    /**
     * Dry-run a locally finalized transaction (drongo {@code BtqPsbtSigner.finalise}) against Core's
     * default policy, verifying Core's reported ids match the local bytes.
     */
    public FinalizedTransaction verifyFinalized(Transaction transaction) {
        Objects.requireNonNull(transaction, "transaction");
        String hex = HEX.formatHex(transaction.bitcoinSerialize());
        String localTxid = transaction.getTxId().toString();
        String localWtxid = transaction.getWTxId().toString();
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
        if(!txid.matches("[0-9a-fA-F]{64}") || !txid.equalsIgnoreCase(localTxid)) {
            throw new IllegalStateException("BTQ Core returned a transaction id inconsistent with finalized bytes");
        }
        String wtxid = requiredString(result, "wtxid", "testmempoolaccept");
        if(!wtxid.matches("[0-9a-fA-F]{64}") || !wtxid.equalsIgnoreCase(localWtxid)) {
            throw new IllegalStateException("BTQ Core returned a witness transaction id inconsistent with finalized bytes");
        }
        return new FinalizedTransaction(hex, localTxid, localWtxid);
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

    /** The BTQ network of this connection. */
    public BtqNetwork network() {
        return config.network();
    }

    /** Whether Core already tracks this address as watch-only P2MR metadata (registration is not idempotent, so callers check first). */
    public boolean isAddressRegistered(String address) {
        JsonObject info = walletRpc.callObject("getaddressinfo", address);
        return optionalBoolean(info, "ismine", false) && optionalBoolean(info, "solvable", false)
                && optionalBoolean(info, "isdilithium", false);
    }

    private void requirePrivateKeysDisabled() {
        JsonObject info = walletRpc.callObject("getwalletinfo");
        if(optionalBoolean(info, "private_keys_enabled", true)
                || !optionalBoolean(info, "descriptors", false)) {
            throw new IllegalStateException("BTQ custody requires a private-key-disabled descriptor wallet");
        }
    }

    /** Parse an address as same-network P2MR via drongo, or return null. */
    private P2MRAddress parseP2mrAddress(String address) {
        try {
            Address parsed = Address.fromString(config.network().toNetwork(), address);
            return parsed instanceof P2MRAddress p2mrAddress ? p2mrAddress : null;
        } catch(InvalidAddressException e) {
            return null;
        }
    }

    @Override
    public void close() {
        config.close();
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

    private static boolean requiredBoolean(JsonObject object, String field, String method) {
        if(!object.has(field) || object.get(field).isJsonNull() || !object.get(field).isJsonPrimitive()
                || !object.get(field).getAsJsonPrimitive().isBoolean()) {
            throw new IllegalStateException(method + " did not return boolean " + field);
        }
        return object.get(field).getAsBoolean();
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

    public record NodeStatus(String subversion, BtqNetwork network, String genesisHash,
                             int blocks, int headers, boolean initialBlockDownload,
                             boolean pruned, int pruneHeight) {
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

    public record FinalizedTransaction(String hex, String txid, String wtxid) {
        public FinalizedTransaction {
            if(hex == null || hex.isBlank()) throw new IllegalArgumentException("transaction hex is required");
            if(txid == null || !txid.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("transaction id must be lowercase 32-byte hexadecimal");
            }
            if(wtxid == null || !wtxid.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("witness transaction id must be lowercase 32-byte hexadecimal");
            }
        }
    }

    public record BroadcastResult(String txid) {
    }
}
