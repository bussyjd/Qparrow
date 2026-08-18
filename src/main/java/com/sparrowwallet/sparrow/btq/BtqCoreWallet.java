// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Node-backed quantum-safe wallet facade.
 *
 * BTQ Core owns all ML-DSA secret material and constructs/signs P2MR witnesses.
 * Qparrow handles only public metadata, unsigned/signed transaction payloads and
 * explicit user intent.
 */
public final class BtqCoreWallet {
    private static final String P2MR_SCRIPT_PREFIX = "5220"; // OP_2 PUSH32
    private static final Pattern P2MR_ID = Pattern.compile("[0-9a-fA-F]{16}");

    private final BtqNodeConfig config;
    private final BtqRpcClient nodeRpc;
    private final BtqRpcClient walletRpc;

    public BtqCoreWallet(BtqNodeConfig config) {
        this(config, new BtqRpcClient(config));
    }

    public BtqCoreWallet(BtqNodeConfig config, BtqRpcClient rpcClient) {
        this.config = Objects.requireNonNull(config, "config");
        this.nodeRpc = Objects.requireNonNull(rpcClient, "rpcClient").node();
        this.walletRpc = rpcClient.wallet();
    }

    /** Verify that the endpoint is BTQ Core on the configured chain. */
    public NodeStatus verifyNode() {
        JsonObject networkInfo = nodeRpc.callObject("getnetworkinfo");
        JsonObject blockchainInfo = nodeRpc.callObject("getblockchaininfo");
        String subversion = requiredString(networkInfo, "subversion", "getnetworkinfo");
        String chain = requiredString(blockchainInfo, "chain", "getblockchaininfo");
        if(!subversion.toLowerCase(Locale.ROOT).contains("btq")) {
            throw new IllegalStateException("Connected node does not identify as BTQ Core: " + subversion);
        }
        if(!config.network().rpcChain().equals(chain)) {
            throw new IllegalStateException("BTQ network mismatch: expected " + config.network().rpcChain() + " but node reports " + chain);
        }

        int blocks = requiredInt(blockchainInfo, "blocks", "getblockchaininfo");
        int headers = requiredInt(blockchainInfo, "headers", "getblockchaininfo");
        boolean initialBlockDownload = optionalBoolean(blockchainInfo, "initialblockdownload", false);
        return new NodeStatus(subversion, config.network(), blocks, headers, initialBlockDownload);
    }

    /** Create or load the configured descriptor wallet. P2MR metadata remains BTQ Core-owned. */
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
            JsonObject walletDir = nodeRpc.callObject("listwalletdir");
            JsonArray wallets = walletDir.getAsJsonArray("wallets");
            if(wallets != null) {
                for(JsonElement element : wallets) {
                    if(config.walletName().equals(requiredString(element.getAsJsonObject(), "name", "listwalletdir"))) {
                        exists = true;
                        break;
                    }
                }
            }

            if(exists) {
                nodeRpc.call("loadwallet", config.walletName(), true);
            } else {
                nodeRpc.call("createwallet", config.walletName(), false, false, "", true, true, true, false);
            }
        }

        JsonObject info = walletRpc.callObject("getwalletinfo");
        WalletStatus status = new WalletStatus(
                requiredString(info, "walletname", "getwalletinfo"),
                optionalInt(info, "walletversion", 0),
                optionalBoolean(info, "descriptors", false),
                optionalBoolean(info, "private_keys_enabled", true),
                optionalInt(info, "txcount", 0)
        );
        if(!config.walletName().equals(status.name())) {
            throw new IllegalStateException("BTQ Core returned wallet info for an unexpected wallet");
        }
        if(!status.descriptors() || !status.privateKeysEnabled()) {
            throw new IllegalStateException("Qparrow requires a descriptor BTQ Core wallet with private keys enabled");
        }
        return status;
    }

    /**
     * Return only UTXOs whose address and script match BTQ Core's persisted
     * P2MR metadata. This prevents inherited/classical wallet outputs from
     * being presented as quantum-safe funds.
     */
    public QuantumBalance getQuantumBalance() {
        List<P2mrEntry> entries = listQuantumAddresses();
        if(entries.isEmpty()) {
            return new QuantumBalance(BigDecimal.ZERO, BigDecimal.ZERO, BigDecimal.ZERO, 0);
        }

        Map<String, P2mrEntry> entriesByAddress = new HashMap<>();
        List<String> addresses = new ArrayList<>();
        for(P2mrEntry entry : entries) {
            entriesByAddress.put(entry.address(), entry);
            addresses.add(entry.address());
        }

        BigDecimal confirmed = BigDecimal.ZERO;
        BigDecimal pending = BigDecimal.ZERO;
        int count = 0;
        for(JsonElement element : walletRpc.callArray("listunspent", 0, 9999999, addresses, true)) {
            JsonObject utxo = element.getAsJsonObject();
            String address = requiredString(utxo, "address", "listunspent");
            String scriptPubKey = requiredString(utxo, "scriptPubKey", "listunspent");
            P2mrEntry entry = entriesByAddress.get(address);
            if(entry == null || !entry.scriptPubKey().equalsIgnoreCase(scriptPubKey)) {
                throw new IllegalStateException("BTQ Core returned inconsistent P2MR UTXO metadata");
            }
            BigDecimal amount = requiredAmount(utxo, "amount", "listunspent");
            int confirmations = requiredInt(utxo, "confirmations", "listunspent");
            if(confirmations > 0) {
                confirmed = confirmed.add(amount);
            } else {
                pending = pending.add(amount);
            }
            count++;
        }
        return new QuantumBalance(confirmed.add(pending), confirmed, pending, count);
    }

    public P2mrAddress newQuantumAddress(String label) {
        JsonObject result = walletRpc.callObject("getnewdilithiumaddress", label == null ? "" : label, "p2mr");
        P2mrAddress address = new P2mrAddress(
                requiredString(result, "address", "getnewdilithiumaddress"),
                requiredString(result, "p2mr_id", "getnewdilithiumaddress"),
                requiredString(result, "scriptPubKey", "getnewdilithiumaddress"),
                requiredString(result, "merkle_root", "getnewdilithiumaddress")
        );
        validateQuantumAddress(address);

        JsonObject info = walletRpc.callObject("getaddressinfo", address.address());
        if(!optionalBoolean(info, "isdilithium", false) || !optionalBoolean(info, "solvable", false)) {
            throw new IllegalStateException("BTQ Core returned an address that is not a solvable Dilithium destination");
        }
        if(info.has("scriptPubKey") && !address.scriptPubKey().equalsIgnoreCase(info.get("scriptPubKey").getAsString())) {
            throw new IllegalStateException("BTQ Core returned inconsistent P2MR scriptPubKey metadata");
        }
        return address;
    }

    public List<P2mrEntry> listQuantumAddresses() {
        List<P2mrEntry> entries = new ArrayList<>();
        for(JsonElement element : walletRpc.callArray("listp2mr")) {
            JsonObject object = element.getAsJsonObject();
            P2mrEntry entry = new P2mrEntry(
                    requiredString(object, "id", "listp2mr"),
                    requiredString(object, "address", "listp2mr"),
                    requiredString(object, "scriptPubKey", "listp2mr"),
                    requiredString(object, "merkle_root", "listp2mr"),
                    object.has("created_at") ? object.get("created_at").getAsLong() : 0L,
                    optionalString(object, "label", ""),
                    optionalString(object, "state", "")
            );
            validateQuantumAddress(new P2mrAddress(entry.address(), entry.id(), entry.scriptPubKey(), entry.merkleRoot()));
            entries.add(entry);
        }
        return List.copyOf(entries);
    }

    public SpendDraft createSpend(String p2mrId, String destination, BigDecimal amount, BigDecimal fee) {
        requireNonBlank(p2mrId, "p2mrId");
        if(!P2MR_ID.matcher(p2mrId).matches()) {
            throw new IllegalArgumentException("p2mrId must be a 16-character hexadecimal BTQ metadata id");
        }
        requireNonBlank(destination, "destination");
        if(!BtqP2mrAddressCodec.isCanonicalAddress(config.network(), destination)) {
            throw new IllegalArgumentException("Qparrow sends only to BTQ P2MR addresses on " + config.network());
        }
        validatePositiveAmount(amount, "amount");
        validatePositiveAmount(fee, "fee");
        JsonObject result = walletRpc.callObject("createp2mrspend", p2mrId, destination, amount, fee);
        String returnedId = requiredString(result, "p2mr_id", "createp2mrspend");
        if(!p2mrId.equals(returnedId)) {
            throw new IllegalStateException("BTQ Core used an unexpected P2MR metadata id");
        }
        return new SpendDraft(
                requiredHex(result, "hex", "createp2mrspend"),
                requiredTxid(result, "txid", "createp2mrspend"),
                returnedId,
                requiredAmount(result, "input_amount", "createp2mrspend"),
                requiredAmount(result, "effective_fee", "createp2mrspend"),
                requiredAmount(result, "change_amount", "createp2mrspend")
        );
    }

    public SignedTransaction signSpend(SpendDraft draft) {
        Objects.requireNonNull(draft, "draft");
        JsonObject result = walletRpc.callObject("signp2mrtransaction", draft.hex(), draft.p2mrId());
        return new SignedTransaction(requiredHex(result, "hex", "signp2mrtransaction"), requiredBoolean(result, "complete", "signp2mrtransaction"));
    }

    public MempoolAcceptance dryRun(SignedTransaction signedTransaction) {
        Objects.requireNonNull(signedTransaction, "signedTransaction");
        if(!signedTransaction.complete()) {
            throw new IllegalStateException("Refusing to test or broadcast an incomplete P2MR transaction");
        }
        JsonArray result = walletRpc.callArray("testp2mrtransaction", signedTransaction.hex());
        if(result.size() != 1) {
            throw new IllegalStateException("BTQ Core returned an unexpected testp2mrtransaction result count");
        }
        JsonObject acceptance = result.get(0).getAsJsonObject();
        return new MempoolAcceptance(
                requiredTxid(acceptance, "txid", "testp2mrtransaction"),
                requiredBoolean(acceptance, "allowed", "testp2mrtransaction"),
                optionalString(acceptance, "reject-reason", "")
        );
    }

    /** Broadcast only after BTQ Core reports a complete witness and successful mempool dry run. */
    public BroadcastResult broadcast(SignedTransaction signedTransaction) {
        MempoolAcceptance acceptance = dryRun(signedTransaction);
        if(!acceptance.allowed()) {
            throw new IllegalStateException("BTQ Core rejected the P2MR transaction: " + acceptance.rejectReason());
        }
        String txid = walletRpc.callString("sendrawtransaction", signedTransaction.hex());
        if(txid.length() != 64 || !isHex(txid)) {
            throw new IllegalStateException("BTQ Core returned an invalid broadcast txid");
        }
        if(!acceptance.txid().equalsIgnoreCase(txid)) {
            throw new IllegalStateException("Broadcast txid does not match the dry-run txid");
        }
        return new BroadcastResult(txid, acceptance);
    }

    /** Preserve BTQ PSBT as opaque base64; never pass it through the Bitcoin-only Drongo parser. */
    public ProcessedPsbt processPsbt(String base64Psbt) {
        requireNonBlank(base64Psbt, "base64Psbt");
        JsonObject result = walletRpc.callObject("walletprocesspsbt", base64Psbt);
        return new ProcessedPsbt(requiredString(result, "psbt", "walletprocesspsbt"), requiredBoolean(result, "complete", "walletprocesspsbt"));
    }

    public String combinePsbts(List<String> base64Psbts) {
        if(base64Psbts == null || base64Psbts.size() < 2 || base64Psbts.stream().anyMatch(value -> value == null || value.isBlank())) {
            throw new IllegalArgumentException("At least two non-empty BTQ PSBTs are required");
        }
        return nodeRpc.callString("combinepsbt", base64Psbts);
    }

    public FinalizedPsbt finalizePsbt(String base64Psbt) {
        requireNonBlank(base64Psbt, "base64Psbt");
        JsonObject result = nodeRpc.callObject("finalizepsbt", base64Psbt, true);
        boolean complete = requiredBoolean(result, "complete", "finalizepsbt");
        String hex = optionalString(result, "hex", "");
        String psbt = optionalString(result, "psbt", "");
        if(complete && hex.isBlank()) {
            throw new IllegalStateException("BTQ Core finalized a PSBT without returning transaction hex");
        }
        return new FinalizedPsbt(complete, hex, psbt);
    }

    private void validateQuantumAddress(P2mrAddress address) {
        requireNonBlank(address.address(), "address");
        requireNonBlank(address.p2mrId(), "p2mrId");
        if(!P2MR_ID.matcher(address.p2mrId()).matches()) {
            throw new IllegalStateException("BTQ Core returned an invalid P2MR metadata id");
        }
        if(address.merkleRoot().length() != 64 || !isHex(address.merkleRoot())) {
            throw new IllegalStateException("BTQ Core returned an invalid P2MR merkle root");
        }
        String expectedAddress = BtqP2mrAddressCodec.encode(config.network(), address.merkleRoot());
        if(!expectedAddress.equals(address.address())) {
            throw new IllegalStateException("BTQ Core returned a non-canonical, wrong-network, or inconsistent P2MR address: " + address.address());
        }
        String expectedScript = P2MR_SCRIPT_PREFIX + address.merkleRoot().toLowerCase(Locale.ROOT);
        if(!expectedScript.equals(address.scriptPubKey().toLowerCase(Locale.ROOT))) {
            throw new IllegalStateException("BTQ Core returned an invalid or inconsistent witness-v2 P2MR scriptPubKey");
        }
    }

    private static String requiredString(JsonObject object, String field, String method) {
        if(!object.has(field) || object.get(field).isJsonNull() || !object.get(field).isJsonPrimitive()
                || !object.get(field).getAsJsonPrimitive().isString()) {
            throw new IllegalStateException("BTQ RPC " + method + " omitted string field '" + field + "'");
        }
        String value = object.get(field).getAsString();
        if(value.isBlank()) {
            throw new IllegalStateException("BTQ RPC " + method + " returned an empty '" + field + "'");
        }
        return value;
    }

    private static String requiredHex(JsonObject object, String field, String method) {
        String value = requiredString(object, field, method);
        if((value.length() & 1) != 0 || !isHex(value)) {
            throw new IllegalStateException("BTQ RPC " + method + " returned non-hex '" + field + "'");
        }
        return value;
    }

    private static String requiredTxid(JsonObject object, String field, String method) {
        String value = requiredHex(object, field, method);
        if(value.length() != 64) {
            throw new IllegalStateException("BTQ RPC " + method + " returned an invalid transaction id in '" + field + "'");
        }
        return value;
    }

    private static boolean requiredBoolean(JsonObject object, String field, String method) {
        if(!object.has(field) || !object.get(field).isJsonPrimitive() || !object.get(field).getAsJsonPrimitive().isBoolean()) {
            throw new IllegalStateException("BTQ RPC " + method + " omitted boolean field '" + field + "'");
        }
        return object.get(field).getAsBoolean();
    }

    private static BigDecimal requiredAmount(JsonObject object, String field, String method) {
        if(!object.has(field) || !object.get(field).isJsonPrimitive() || !object.get(field).getAsJsonPrimitive().isNumber()) {
            throw new IllegalStateException("BTQ RPC " + method + " omitted amount field '" + field + "'");
        }
        return object.get(field).getAsBigDecimal();
    }

    private static int requiredInt(JsonObject object, String field, String method) {
        if(!object.has(field) || !object.get(field).isJsonPrimitive() || !object.get(field).getAsJsonPrimitive().isNumber()) {
            throw new IllegalStateException("BTQ RPC " + method + " omitted number field '" + field + "'");
        }
        return object.get(field).getAsInt();
    }

    private static String optionalString(JsonObject object, String field, String defaultValue) {
        return object.has(field) && !object.get(field).isJsonNull() ? object.get(field).getAsString() : defaultValue;
    }

    private static int optionalInt(JsonObject object, String field, int defaultValue) {
        return object.has(field) && !object.get(field).isJsonNull() ? object.get(field).getAsInt() : defaultValue;
    }

    private static boolean optionalBoolean(JsonObject object, String field, boolean defaultValue) {
        return object.has(field) && !object.get(field).isJsonNull() ? object.get(field).getAsBoolean() : defaultValue;
    }

    private static void validatePositiveAmount(BigDecimal amount, String field) {
        Objects.requireNonNull(amount, field);
        if(amount.signum() <= 0 || amount.scale() > 8) {
            throw new IllegalArgumentException(field + " must be positive with at most 8 decimal places");
        }
    }

    private static void requireNonBlank(String value, String field) {
        if(value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }

    private static boolean isHex(String value) {
        for(int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if(Character.digit(c, 16) < 0) {
                return false;
            }
        }
        return true;
    }

    public record NodeStatus(String subversion, BtqNetwork network, int blocks, int headers, boolean initialBlockDownload) {}
    public record WalletStatus(String name, int version, boolean descriptors, boolean privateKeysEnabled, int transactionCount) {}
    public record QuantumBalance(BigDecimal total, BigDecimal confirmed, BigDecimal pending, int utxoCount) {}
    public record P2mrAddress(String address, String p2mrId, String scriptPubKey, String merkleRoot) {}
    public record P2mrEntry(String id, String address, String scriptPubKey, String merkleRoot, long createdAt, String label, String state) {}
    public record SpendDraft(String hex, String txid, String p2mrId, BigDecimal inputAmount, BigDecimal effectiveFee, BigDecimal changeAmount) {}
    public record SignedTransaction(String hex, boolean complete) {}
    public record MempoolAcceptance(String txid, boolean allowed, String rejectReason) {}
    public record BroadcastResult(String txid, MempoolAcceptance acceptance) {}
    public record ProcessedPsbt(String psbt, boolean complete) {}
    public record FinalizedPsbt(boolean complete, String hex, String psbt) {}
}
