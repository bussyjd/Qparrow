// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BtqCoreWalletTest {
    private static final String ROOT = "/";
    private static final String WALLET = "/wallet/qparrow_test";
    private static final String TXID = "ab".repeat(32);
    private static final String P2MR_ID = "aa".repeat(8);
    private static final String MERKLE_ROOT = "11".repeat(32);
    private static final String SCRIPT_PUB_KEY = "5220" + MERKLE_ROOT;
    private static final String ADDRESS = BtqP2mrAddressCodec.encode(BtqNetwork.REGTEST, MERKLE_ROOT);

    @Test
    void verifiesBtqIdentityAndCreatesDescriptorWallet() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(ROOT, "getnetworkinfo", object("subversion", "/BTQ:0.4.4/"))
                .expect(ROOT, "getblockchaininfo", object("chain", "regtest", "blocks", 100, "headers", 100, "initialblockdownload", false))
                .expect(ROOT, "listwallets", array())
                .expect(ROOT, "listwalletdir", object("wallets", array()))
                .expect(ROOT, "createwallet", object("name", "qparrow_test"))
                .expect(WALLET, "getwalletinfo", object("walletname", "qparrow_test", "walletversion", 169900, "descriptors", true, "private_keys_enabled", true, "txcount", 0));
        BtqCoreWallet wallet = wallet(transport);

        BtqCoreWallet.NodeStatus nodeStatus = wallet.verifyNode();
        BtqCoreWallet.WalletStatus walletStatus = wallet.ensureWallet();

        assertEquals(BtqNetwork.REGTEST, nodeStatus.network());
        assertEquals(100, nodeStatus.blocks());
        assertTrue(walletStatus.descriptors());
        assertTrue(walletStatus.privateKeysEnabled());
        JsonArray createParams = transport.paramsFor("createwallet");
        assertEquals("qparrow_test", createParams.get(0).getAsString());
        assertTrue(createParams.get(5).getAsBoolean(), "Qparrow must request a descriptor wallet");
        transport.assertExhausted();
    }

    @Test
    void refusesLoadedWalletWithoutRequiredCustodyBoundary() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(ROOT, "listwallets", array(new com.google.gson.JsonPrimitive("qparrow_test")))
                .expect(WALLET, "getwalletinfo", object(
                        "walletname", "qparrow_test",
                        "descriptors", false,
                        "private_keys_enabled", true));

        IllegalStateException error = assertThrows(IllegalStateException.class, () -> wallet(transport).ensureWallet());

        assertTrue(error.getMessage().contains("descriptor"));
        transport.assertExhausted();
    }

    @Test
    void rejectsBitcoinCoreAndWrongNetwork() {
        ScriptedTransport bitcoin = new ScriptedTransport()
                .expect(ROOT, "getnetworkinfo", object("subversion", "/Satoshi:26.0/"))
                .expect(ROOT, "getblockchaininfo", object("chain", "regtest", "blocks", 1, "headers", 1));
        assertThrows(IllegalStateException.class, () -> wallet(bitcoin).verifyNode());

        ScriptedTransport wrongNetwork = new ScriptedTransport()
                .expect(ROOT, "getnetworkinfo", object("subversion", "/BTQ:0.4.4/"))
                .expect(ROOT, "getblockchaininfo", object("chain", "main", "blocks", 1, "headers", 1));
        assertThrows(IllegalStateException.class, () -> wallet(wrongNetwork).verifyNode());
    }

    @Test
    void createsAndValidatesDilithiumP2mrAddress() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "getnewdilithiumaddress", object("address", ADDRESS, "p2mr_id", P2MR_ID, "scriptPubKey", SCRIPT_PUB_KEY, "merkle_root", MERKLE_ROOT))
                .expect(WALLET, "getaddressinfo", object("isdilithium", true, "solvable", true, "scriptPubKey", SCRIPT_PUB_KEY));

        BtqCoreWallet.P2mrAddress address = wallet(transport).newQuantumAddress("salary");

        assertEquals(P2MR_ID, address.p2mrId());
        assertTrue(address.address().startsWith(BtqNetwork.REGTEST.p2mrPrefix()));
        JsonArray params = transport.paramsFor("getnewdilithiumaddress");
        assertEquals("salary", params.get(0).getAsString());
        assertEquals("p2mr", params.get(1).getAsString());
        transport.assertExhausted();
    }

    @Test
    void rejectsMalformedOrClassicalReceiveAddress() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "getnewdilithiumaddress", object("address", "bcrt1qclassical", "p2mr_id", P2MR_ID, "scriptPubKey", "0014" + "11".repeat(20), "merkle_root", MERKLE_ROOT));

        assertThrows(IllegalStateException.class, () -> wallet(transport).newQuantumAddress(""));
        transport.assertExhausted();
    }

    @Test
    void rejectsP2mrAddressThatDoesNotCommitToReturnedRoot() {
        String otherRoot = "22".repeat(32);
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "getnewdilithiumaddress", object(
                        "address", ADDRESS,
                        "p2mr_id", P2MR_ID,
                        "scriptPubKey", SCRIPT_PUB_KEY,
                        "merkle_root", otherRoot));

        assertThrows(IllegalStateException.class, () -> wallet(transport).newQuantumAddress(""));
        transport.assertExhausted();
    }

    @Test
    void reportsOnlyMetadataMatchedP2mrBalance() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "listp2mr", array(object(
                        "id", P2MR_ID,
                        "address", ADDRESS,
                        "scriptPubKey", SCRIPT_PUB_KEY,
                        "merkle_root", MERKLE_ROOT,
                        "created_at", 100,
                        "label", "savings",
                        "state", "active")))
                .expect(WALLET, "listunspent", array(
                        object("address", ADDRESS, "scriptPubKey", SCRIPT_PUB_KEY, "amount", 1.25, "confirmations", 6),
                        object("address", ADDRESS, "scriptPubKey", SCRIPT_PUB_KEY, "amount", 0.5, "confirmations", 0)));

        BtqCoreWallet.QuantumBalance balance = wallet(transport).getQuantumBalance();

        assertEquals(new BigDecimal("1.75"), balance.total());
        assertEquals(new BigDecimal("1.25"), balance.confirmed());
        assertEquals(new BigDecimal("0.5"), balance.pending());
        assertEquals(2, balance.utxoCount());
        JsonArray params = transport.paramsFor("listunspent");
        assertEquals(ADDRESS, params.get(2).getAsJsonArray().get(0).getAsString());
        transport.assertExhausted();
    }

    @Test
    void createsSignsDryRunsAndBroadcastsP2mrSpend() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "createp2mrspend", object("hex", "02000000", "txid", TXID, "p2mr_id", P2MR_ID, "input_amount", 1.0, "effective_fee", 0.00001, "change_amount", 0.49999))
                .expect(WALLET, "signp2mrtransaction", object("hex", "020000000001", "complete", true))
                .expect(WALLET, "testp2mrtransaction", array(object("txid", TXID, "allowed", true)))
                .expect(WALLET, "sendrawtransaction", TXID);
        BtqCoreWallet wallet = wallet(transport);

        BtqCoreWallet.SpendDraft draft = wallet.createSpend(P2MR_ID, ADDRESS, new BigDecimal("0.5"), new BigDecimal("0.00001"));
        BtqCoreWallet.SignedTransaction signed = wallet.signSpend(draft);
        BtqCoreWallet.BroadcastResult broadcast = wallet.broadcast(signed);

        assertEquals(TXID, broadcast.txid());
        assertTrue(signed.complete());
        assertTrue(broadcast.acceptance().allowed());
        transport.assertExhausted();
    }

    @Test
    void refusesClassicalDestinationBeforeCallingNode() {
        ScriptedTransport transport = new ScriptedTransport();

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> wallet(transport).createSpend(P2MR_ID, "bcrt1qclassical", new BigDecimal("0.5"), new BigDecimal("0.00001")));

        assertTrue(error.getMessage().contains("only to BTQ P2MR"));
        transport.assertExhausted();
    }

    @Test
    void refusesInvalidP2mrMetadataIdAndCorruptP2mrDestinationBeforeCallingNode() {
        ScriptedTransport transport = new ScriptedTransport();

        assertThrows(IllegalArgumentException.class,
                () -> wallet(transport).createSpend("not-an-id", ADDRESS, new BigDecimal("0.5"), new BigDecimal("0.00001")));
        String corrupt = ADDRESS.substring(0, ADDRESS.length() - 1) + (ADDRESS.endsWith("q") ? "p" : "q");
        assertThrows(IllegalArgumentException.class,
                () -> wallet(transport).createSpend(P2MR_ID, corrupt, new BigDecimal("0.5"), new BigDecimal("0.00001")));
        transport.assertExhausted();
    }

    @Test
    void refusesIncompleteOrRejectedTransactionBeforeBroadcast() {
        ScriptedTransport incompleteTransport = new ScriptedTransport();
        assertThrows(IllegalStateException.class, () -> wallet(incompleteTransport).broadcast(new BtqCoreWallet.SignedTransaction("00", false)));
        incompleteTransport.assertExhausted();

        ScriptedTransport rejectedTransport = new ScriptedTransport()
                .expect(WALLET, "testp2mrtransaction", array(object("txid", TXID, "allowed", false, "reject-reason", "mandatory-script-verify-flag-failed")));
        IllegalStateException rejected = assertThrows(IllegalStateException.class, () -> wallet(rejectedTransport).broadcast(new BtqCoreWallet.SignedTransaction("020000000001", true)));
        assertTrue(rejected.getMessage().contains("mandatory-script"));
        rejectedTransport.assertExhausted();
    }

    @Test
    void preservesBtqPsbtAsOpaqueBase64() {
        String unsigned = "cHNidP8BAFQCAAAA";
        String signedA = unsigned + "A19P2MR";
        String signedB = unsigned + "B1BDILI";
        String combined = unsigned + "COMBINED";
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "walletprocesspsbt", object("psbt", signedA, "complete", false))
                .expect(ROOT, "combinepsbt", combined)
                .expect(ROOT, "finalizepsbt", object("complete", true, "hex", "020000000001"));
        BtqCoreWallet wallet = wallet(transport);

        assertEquals(signedA, wallet.processPsbt(unsigned).psbt());
        assertEquals(combined, wallet.combinePsbts(List.of(signedA, signedB)));
        assertEquals("020000000001", wallet.finalizePsbt(combined).hex());
        assertEquals(unsigned, transport.paramsFor("walletprocesspsbt").get(0).getAsString());
        assertEquals(signedA, transport.paramsFor("combinepsbt").get(0).getAsJsonArray().get(0).getAsString());
        transport.assertExhausted();
    }

    @Test
    void mapsRpcErrorsWithoutLeakingCredentials() {
        ScriptedTransport transport = new ScriptedTransport().expectError(WALLET, "listp2mr", -13, "wallet passphrase needed");

        BtqRpcException error = assertThrows(BtqRpcException.class, () -> wallet(transport).listQuantumAddresses());

        assertEquals(-13, error.getCode());
        assertEquals("listp2mr", error.getMethod());
        assertFalse(error.getMessage().contains("Basic"));
        transport.assertExhausted();
    }

    private static BtqCoreWallet wallet(ScriptedTransport transport) {
        BtqNodeConfig config = new BtqNodeConfig(URI.create("http://127.0.0.1:18443/"), "qparrow_test", BtqNetwork.REGTEST, BtqRpcCredentials.none(), Duration.ofSeconds(5));
        return new BtqCoreWallet(config, new BtqRpcClient(config, transport));
    }

    private static JsonObject object(Object... fields) {
        JsonObject object = new JsonObject();
        for(int i = 0; i < fields.length; i += 2) {
            Object value = fields[i + 1];
            if(value instanceof JsonElement jsonElement) {
                object.add((String)fields[i], jsonElement);
            } else if(value instanceof Boolean bool) {
                object.addProperty((String)fields[i], bool);
            } else if(value instanceof Number number) {
                object.addProperty((String)fields[i], number);
            } else {
                object.addProperty((String)fields[i], (String)value);
            }
        }
        return object;
    }

    private static JsonArray array(JsonElement... elements) {
        JsonArray array = new JsonArray();
        for(JsonElement element : elements) {
            array.add(element);
        }
        return array;
    }

    private record Expectation(String path, String method, JsonElement result, JsonObject error) {}

    private static final class ScriptedTransport implements BtqRpcTransport {
        private final Deque<Expectation> expectations = new ArrayDeque<>();
        private final List<JsonObject> requests = new ArrayList<>();

        ScriptedTransport expect(String path, String method, String result) {
            return expect(path, method, JsonParser.parseString('"' + result + '"'));
        }

        ScriptedTransport expect(String path, String method, JsonElement result) {
            expectations.add(new Expectation(path, method, result, null));
            return this;
        }

        ScriptedTransport expectError(String path, String method, int code, String message) {
            expectations.add(new Expectation(path, method, null, object("code", code, "message", message)));
            return this;
        }

        @Override
        public JsonObject send(URI endpoint, String authorizationHeader, Duration timeout, JsonObject request) {
            if(expectations.isEmpty()) {
                throw new AssertionError("Unexpected BTQ RPC request: " + request);
            }
            Expectation expectation = expectations.removeFirst();
            assertEquals(expectation.path(), endpoint.getPath());
            assertEquals(expectation.method(), request.get("method").getAsString());
            requests.add(request.deepCopy());

            JsonObject response = new JsonObject();
            response.addProperty("id", request.get("id").getAsLong());
            response.add("result", expectation.result() == null ? JsonNull.INSTANCE : expectation.result());
            response.add("error", expectation.error() == null ? JsonNull.INSTANCE : expectation.error());
            return response;
        }

        JsonArray paramsFor(String method) {
            return requests.stream()
                    .filter(request -> method.equals(request.get("method").getAsString()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("No request for " + method))
                    .getAsJsonArray("params");
        }

        void assertExhausted() {
            assertTrue(expectations.isEmpty(), "Unsent expected RPC requests: " + expectations);
        }
    }
}
