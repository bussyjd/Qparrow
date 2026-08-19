// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.sparrowwallet.sparrow.btq.*;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BtqWatchOnlyCoreTest {
    private static final String ROOT = "/";
    private static final String WALLET = "/wallet/qparrow_custody";
    private static final String FINALIZED_TX = "02000000000101" + "00".repeat(32)
            + "0000000000ffffffff01e803000000000000015101010100000000";
    private static final String FINALIZED_TXID = "4b01e7b3c8b285c6b1151720d4467564813a8048a80b17f5b0521c9d0aedff66";

    @Test
    void verifiesBtqIdentityChainAndSynchronizationData() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(ROOT, "getnetworkinfo", object("subversion", "/BTQ Core:0.4.4/"))
                .expect(ROOT, "getblockchaininfo", object(
                        "chain", "regtest", "blocks", 22, "headers", 24, "initialblockdownload", true));

        BtqWatchOnlyCore.NodeStatus status = core(transport).verifyNode();

        assertEquals(BtqNetwork.REGTEST, status.network());
        assertEquals(22, status.blocks());
        assertEquals(24, status.headers());
        assertTrue(status.initialBlockDownload());
        transport.assertExhausted();
    }

    @Test
    void createsOnlyAPrivateKeyDisabledWallet() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(ROOT, "listwallets", array())
                .expect(ROOT, "listwalletdir", object("wallets", array()))
                .expect(ROOT, "createwallet", object("name", "qparrow_custody"))
                .expect(WALLET, "getwalletinfo", object(
                        "walletname", "qparrow_custody",
                        "descriptors", true,
                        "private_keys_enabled", false,
                        "blank", true));

        BtqWatchOnlyCore.WalletStatus status = core(transport).ensureWallet();

        assertFalse(status.privateKeysEnabled());
        JsonArray parameters = transport.parameters("createwallet");
        assertTrue(parameters.get(1).getAsBoolean(), "disable_private_keys must be true");
        assertTrue(parameters.get(2).getAsBoolean(), "watch-only wallet must be blank");
        assertTrue(parameters.get(5).getAsBoolean(), "watch-only wallet must use descriptors");
        transport.assertExhausted();
    }

    @Test
    void refusesAnyLoadedWalletThatCanHoldPrivateKeys() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(ROOT, "listwallets", array(string("qparrow_custody")))
                .expect(WALLET, "getwalletinfo", object(
                        "walletname", "qparrow_custody",
                        "descriptors", true,
                        "private_keys_enabled", true,
                        "blank", false));

        assertThrows(IllegalStateException.class, () -> core(transport).ensureWallet());
        transport.assertExhausted();
    }

    @Test
    void registersTheExactLocalLeafAsWatchOnly() {
        BtqP2mrKeyPath.Address local = localAddress();
        String script = HexFormat.of().formatHex(local.scriptPubKey());
        String root = HexFormat.of().formatHex(local.merkleRoot());
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "getwalletinfo", object(
                        "walletname", "qparrow_custody",
                        "descriptors", true,
                        "private_keys_enabled", false,
                        "blank", true))
                .expect(WALLET, "getnewp2mraddress", object(
                        "p2mr_id", "ab".repeat(8),
                        "address", local.address(),
                        "scriptPubKey", script,
                        "merkle_root", root))
                .expect(ROOT, "getdescriptorinfo", object(
                        "descriptor", "addr(" + local.address() + ")#checksum",
                        "isrange", false,
                        "issolvable", false,
                        "hasprivatekeys", false))
                .expect(WALLET, "importdescriptors", array(object("success", true)))
                .expect(WALLET, "getaddressinfo", object(
                        "address", local.address(),
                        "scriptPubKey", script,
                        "ismine", true,
                        "iswatchonly", false,
                        "solvable", true,
                        "isdilithium", true,
                        "witness_version", 2));

        BtqWatchOnlyCore.RegisteredAddress registered = core(transport).registerAddress(local, "receive-0");

        assertEquals(local.address(), registered.address());
        JsonArray parameters = transport.parameters("getnewp2mraddress");
        JsonObject leaf = parameters.get(0).getAsJsonArray().get(0).getAsJsonObject();
        assertEquals(0, leaf.get("depth").getAsInt());
        assertEquals(192, leaf.get("leaf_version").getAsInt());
        assertEquals(HexFormat.of().formatHex(local.leafScript()), leaf.get("script").getAsString());
        transport.assertExhausted();
    }

    @Test
    void rejectsNodeCommitmentSubstitution() {
        BtqP2mrKeyPath.Address local = localAddress();
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "getwalletinfo", object(
                        "walletname", "qparrow_custody",
                        "descriptors", true,
                        "private_keys_enabled", false,
                        "blank", true))
                .expect(WALLET, "getnewp2mraddress", object(
                        "p2mr_id", "ab".repeat(8),
                        "address", local.address(),
                        "scriptPubKey", "5220" + "00".repeat(32),
                        "merkle_root", "00".repeat(32)));

        assertThrows(IllegalStateException.class, () -> core(transport).registerAddress(local, "receive-0"));
        transport.assertExhausted();
    }

    @Test
    void acceptsOnlyTypedCanonicalLocallyWatchedP2mrUtxos() {
        BtqP2mrKeyPath.Address local = localAddress();
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "getwalletinfo", object("descriptors", true, "private_keys_enabled", false))
                .expect(WALLET, "listunspent", array(object(
                        "txid", "34".repeat(32), "vout", 1, "address", local.address(),
                        "scriptPubKey", HexFormat.of().formatHex(local.scriptPubKey()),
                        "amount", "0.00100000", "confirmations", 3)));

        List<BtqWatchOnlyCore.WatchedUtxo> unspent = core(transport).listUtxos(1);

        assertEquals(1, unspent.size());
        assertEquals(100_000L, unspent.get(0).amountSats());
        assertEquals(3, unspent.get(0).confirmations());
        assertFalse(transport.parameters("listunspent").get(3).getAsBoolean(),
                "unsafe UTXOs must not be included");
        transport.assertExhausted();
    }

    @Test
    void recoveryRescansFromGenesisOnlyWithPrivateKeysDisabled() {
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "getwalletinfo", object("descriptors", true, "private_keys_enabled", false))
                .expect(WALLET, "rescanblockchain", object("start_height", 0, "stop_height", 240));

        BtqWatchOnlyCore.RescanResult result = core(transport).rescanFromGenesis();

        assertEquals(0, result.startHeight());
        assertEquals(240, result.stopHeight());
        assertEquals(0, transport.parameters("rescanblockchain").get(0).getAsInt());
        transport.assertExhausted();
    }

    @Test
    void fundsOnlyExplicitInputsWithQuantumChangeAndFinalizesAfterLocalSigning() {
        BtqP2mrKeyPath.Address payment = localAddress(BtqCustodySpec.Chain.RECEIVE, 1);
        BtqP2mrKeyPath.Address change = localAddress(BtqCustodySpec.Chain.CHANGE, 0);
        String fundingTxid = "12".repeat(32);
        ScriptedTransport transport = new ScriptedTransport()
                .expect(WALLET, "getwalletinfo", object(
                        "walletname", "qparrow_custody",
                        "descriptors", true,
                        "private_keys_enabled", false))
                .expect(WALLET, "walletcreatefundedpsbt", object(
                        "psbt", "unsigned-opaque",
                        "fee", "0.00001000",
                        "changepos", 1))
                .expect(ROOT, "finalizepsbt", object(
                        "complete", true,
                        "hex", FINALIZED_TX))
                .expect(ROOT, "testmempoolaccept", array(object(
                        "txid", FINALIZED_TXID,
                        "allowed", true)))
                .expect(ROOT, "sendrawtransaction", string(FINALIZED_TXID));
        BtqWatchOnlyCore core = core(transport);

        BtqWatchOnlyCore.FundedPsbt funded = core.createFundedPsbt(
                List.of(new BtqWatchOnlyCore.Outpoint(fundingTxid, 2)),
                List.of(new BtqWatchOnlyCore.Payment(payment.address(), 10_000_000)),
                change, 2);
        assertEquals(1_000, funded.feeSats());

        JsonArray fundingParameters = transport.parameters("walletcreatefundedpsbt");
        JsonObject selected = fundingParameters.get(0).getAsJsonArray().get(0).getAsJsonObject();
        assertEquals(4402, selected.get("weight").getAsInt());
        JsonObject options = fundingParameters.get(3).getAsJsonObject();
        assertFalse(options.get("add_inputs").getAsBoolean());
        assertTrue(options.get("include_watching").getAsBoolean());
        assertEquals(change.address(), options.get("change_address").getAsString());

        BtqWatchOnlyCore.FinalizedTransaction finalized = core.finalizePsbt(
                new BtqPsbtSigner.SignedPsbt("signed-opaque", 1_000,
                        List.of("00".repeat(32)), FINALIZED_TXID));
        assertEquals(FINALIZED_TXID, finalized.txid());
        assertEquals(FINALIZED_TXID, core.broadcast(finalized).txid());
        transport.assertExhausted();
    }

    @Test
    void rejectsFinalizedTransactionSubstitutionByCore() {
        String substituted = FINALIZED_TX.replace("e803000000000000", "e903000000000000");
        ScriptedTransport transport = new ScriptedTransport()
                .expect(ROOT, "finalizepsbt", object("complete", true, "hex", substituted));

        assertThrows(IllegalStateException.class, () -> core(transport).finalizePsbt(
                new BtqPsbtSigner.SignedPsbt("signed-opaque", 1_000,
                        List.of("00".repeat(32)), FINALIZED_TXID)));
        transport.assertExhausted();
    }

    @Test
    void computesFinalizedTransactionIdLocallyAndRejectsMalformedWitnessSerialization() {
        assertEquals(FINALIZED_TXID, BtqPsbtSigner.finalizedTransactionId(FINALIZED_TX));
        assertThrows(IllegalArgumentException.class,
                () -> BtqPsbtSigner.finalizedTransactionId(FINALIZED_TX + "00"));
        assertThrows(IllegalArgumentException.class,
                () -> BtqPsbtSigner.finalizedTransactionId(FINALIZED_TX.replaceFirst("0001", "0002")));
    }

    private static BtqP2mrKeyPath.Address localAddress() {
        return localAddress(BtqCustodySpec.Chain.RECEIVE, 0);
    }

    private static BtqP2mrKeyPath.Address localAddress(BtqCustodySpec.Chain chain, int index) {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)i;
        }
        return BtqP2mrKeyPath.derive(master, BtqNetwork.REGTEST, chain, index);
    }

    private static BtqWatchOnlyCore core(ScriptedTransport transport) {
        BtqNodeConfig config = new BtqNodeConfig(
                URI.create("http://127.0.0.1:18443/"),
                "qparrow_custody",
                BtqNetwork.REGTEST,
                BtqRpcCredentials.none(),
                Duration.ofSeconds(5));
        return new BtqWatchOnlyCore(config, new BtqRpcClient(config, transport));
    }

    private static JsonObject object(Object... fields) {
        JsonObject object = new JsonObject();
        for(int i = 0; i < fields.length; i += 2) {
            Object value = fields[i + 1];
            if(value instanceof JsonElement element) {
                object.add((String)fields[i], element);
            } else if(value instanceof Boolean bool) {
                object.addProperty((String)fields[i], bool);
            } else if(value instanceof Number number) {
                object.addProperty((String)fields[i], number);
            } else {
                object.addProperty((String)fields[i], String.valueOf(value));
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

    private static JsonElement string(String value) {
        return com.google.gson.JsonParser.parseString('"' + value + '"');
    }

    private record Expectation(String path, String method, JsonElement result) {
    }

    private static final class ScriptedTransport implements BtqRpcTransport {
        private final Deque<Expectation> expectations = new ArrayDeque<>();
        private final java.util.List<JsonObject> requests = new java.util.ArrayList<>();

        private ScriptedTransport expect(String path, String method, JsonElement result) {
            expectations.addLast(new Expectation(path, method, result));
            return this;
        }

        @Override
        public JsonObject send(URI endpoint, String authorizationHeader, Duration timeout, JsonObject request) {
            Expectation expectation = expectations.removeFirst();
            assertEquals(expectation.path(), endpoint.getPath());
            assertEquals(expectation.method(), request.get("method").getAsString());
            requests.add(request.deepCopy());
            JsonObject response = new JsonObject();
            response.addProperty("id", request.get("id").getAsLong());
            response.add("result", expectation.result());
            response.add("error", JsonNull.INSTANCE);
            return response;
        }

        private JsonArray parameters(String method) {
            return requests.stream()
                    .filter(request -> method.equals(request.get("method").getAsString()))
                    .findFirst()
                    .orElseThrow()
                    .getAsJsonArray("params");
        }

        private void assertExhausted() {
            assertTrue(expectations.isEmpty(), "unconsumed RPC expectations: " + expectations);
        }
    }
}
