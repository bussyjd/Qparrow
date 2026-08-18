// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigDecimal;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Real-process proof that Qparrow's opaque RPC flow produces and verifies ML-DSA P2MR witnesses. */
@Tag("btq-integration")
class BtqCoreRegtestIntegrationTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void nodeBackedP2mrAndPsbtFlowsVerifyAgainstBtqCore() throws Exception {
        String binarySetting = System.getenv("BTQ_CORE_BIN");
        assumeTrue(binarySetting != null && !binarySetting.isBlank(), "Set BTQ_CORE_BIN to run the real BTQ Core integration test");
        Path binary = Path.of(binarySetting).toAbsolutePath();
        assumeTrue(Files.isExecutable(binary), "BTQ_CORE_BIN is not executable: " + binary);

        Path dataDirectory = temporaryDirectory.resolve("node");
        Files.createDirectories(dataDirectory);
        int rpcPort = freePort();
        int p2pPort = freePort();
        Path log = temporaryDirectory.resolve("btqd.log");
        Process process = new ProcessBuilder(
                binary.toString(),
                "-regtest",
                "-datadir=" + dataDirectory,
                "-server=1",
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
                "-rpcport=" + rpcPort,
                "-port=" + p2pPort,
                "-listen=0",
                "-dnsseed=0",
                "-discover=0",
                "-fallbackfee=0.00001",
                "-acceptnonstdtxn=1",
                "-printtoconsole=1"
        ).redirectErrorStream(true).redirectOutput(log.toFile()).start();

        Path cookie = dataDirectory.resolve("regtest").resolve(".cookie");
        BtqNodeConfig qparrowConfig = new BtqNodeConfig(
                java.net.URI.create("http://127.0.0.1:" + rpcPort + "/"),
                "qparrow_e2e",
                BtqNetwork.REGTEST,
                BtqRpcCredentials.cookie(cookie),
                Duration.ofSeconds(10));
        BtqNodeConfig minerConfig = new BtqNodeConfig(
                qparrowConfig.rpcUri(),
                "miner_e2e",
                BtqNetwork.REGTEST,
                BtqRpcCredentials.cookie(cookie),
                Duration.ofSeconds(10));

        BtqRpcClient nodeRpc = new BtqRpcClient(qparrowConfig).node();
        try {
            waitForNode(nodeRpc, cookie, process, log);
            BtqCoreWallet qparrow = new BtqCoreWallet(qparrowConfig);
            BtqCoreWallet miner = new BtqCoreWallet(minerConfig);

            BtqCoreWallet.NodeStatus nodeStatus = qparrow.verifyNode();
            assertEquals(BtqNetwork.REGTEST, nodeStatus.network());
            assertTrue(nodeStatus.subversion().toLowerCase().contains("btq"));
            assertTrue(qparrow.ensureWallet().descriptors());
            assertTrue(miner.ensureWallet().descriptors());

            BtqRpcClient minerRpc = new BtqRpcClient(minerConfig).wallet();
            String miningAddress = minerRpc.callString("getnewaddress", "mining", "bech32");
            nodeRpc.callArray("generatetoaddress", 101, miningAddress);

            BtqCoreWallet.P2mrAddress source = qparrow.newQuantumAddress("integration-source");
            BtqCoreWallet.P2mrAddress destination = qparrow.newQuantumAddress("integration-destination");
            assertTrue(source.address().startsWith("qcrt1z"));
            assertEquals(68, source.scriptPubKey().length());
            minerRpc.callString("sendtoaddress", source.address(), new BigDecimal("1.0"));
            nodeRpc.callArray("generatetoaddress", 1, miningAddress);

            BtqCoreWallet.QuantumBalance quantumBalance = qparrow.getQuantumBalance();
            assertEquals(new BigDecimal("1.00000000"), quantumBalance.confirmed());
            assertEquals(1, quantumBalance.utxoCount());

            JsonArray utxos = new BtqRpcClient(qparrowConfig).wallet().callArray("listunspent", 1, 9999999, List.of(source.address()));
            JsonObject utxo = utxos.get(0).getAsJsonObject();
            JsonObject fundedPsbt = new BtqRpcClient(qparrowConfig).wallet().callObject(
                    "walletcreatefundedpsbt",
                    List.of(Map.of("txid", utxo.get("txid").getAsString(), "vout", utxo.get("vout").getAsInt())),
                    List.of(Map.of(destination.address(), new BigDecimal("0.3"))),
                    0,
                    Map.of("add_inputs", false),
                    true);
            String opaquePsbt = fundedPsbt.get("psbt").getAsString();
            BtqCoreWallet.ProcessedPsbt processed = qparrow.processPsbt(opaquePsbt);
            assertTrue(processed.complete(), "BTQ Core must sign the P2MR PSBT input");
            BtqCoreWallet.FinalizedPsbt finalized = qparrow.finalizePsbt(processed.psbt());
            assertTrue(finalized.complete());
            JsonArray psbtAcceptance = nodeRpc.callArray("testmempoolaccept", List.of(finalized.hex()));
            assertTrue(psbtAcceptance.get(0).getAsJsonObject().get("allowed").getAsBoolean());

            BtqCoreWallet.SpendDraft draft = qparrow.createSpend(
                    source.p2mrId(), destination.address(), new BigDecimal("0.4"), new BigDecimal("0.00001"));
            BtqCoreWallet.SignedTransaction signed = qparrow.signSpend(draft);
            assertTrue(signed.complete());

            JsonObject decoded = nodeRpc.callObject("decoderawtransaction", signed.hex());
            JsonArray witness = decoded.getAsJsonArray("vin").get(0).getAsJsonObject().getAsJsonArray("txinwitness");
            String signature = witness.asList().stream()
                    .map(JsonElement::getAsString)
                    .filter(item -> item.length() == 2 * 2421)
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("P2MR witness must contain a 2420-byte ML-DSA signature plus sighash byte"));
            assertTrue(witness.asList().stream().anyMatch(item -> {
                        String itemHex = item.getAsString();
                        return itemHex.length() == 2 * (1312 + 4) && itemHex.startsWith("4d2005");
                    }), "P2MR leaf must embed the 1312-byte ML-DSA public key with PUSHDATA2 and a checksig opcode");

            int signatureOffset = signed.hex().indexOf(signature);
            assertTrue(signatureOffset >= 0, "Decoded ML-DSA signature must be present verbatim in transaction serialization");
            int mutatedByteOffset = signatureOffset + 200;
            String originalByte = signed.hex().substring(mutatedByteOffset, mutatedByteOffset + 2);
            String tamperedHex = signed.hex().substring(0, mutatedByteOffset)
                    + (originalByte.equals("00") ? "01" : "00")
                    + signed.hex().substring(mutatedByteOffset + 2);
            BtqCoreWallet.MempoolAcceptance tampered = qparrow.dryRun(new BtqCoreWallet.SignedTransaction(tamperedHex, true));
            assertFalse(tampered.allowed(), "Mutating the ML-DSA signature must fail P2MR validation");

            BtqCoreWallet.BroadcastResult broadcast = qparrow.broadcast(signed);
            assertEquals(draft.txid(), broadcast.txid());
            nodeRpc.callArray("generatetoaddress", 1, miningAddress);
            JsonObject transaction = new BtqRpcClient(qparrowConfig).wallet().callObject("gettransaction", broadcast.txid(), true, true);
            assertTrue(transaction.get("confirmations").getAsInt() > 0);
        } finally {
            if(process.isAlive()) {
                try {
                    nodeRpc.call("stop");
                } catch(Exception ignored) {
                    process.destroy();
                }
                if(!process.waitFor(10, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                    process.waitFor(5, TimeUnit.SECONDS);
                }
            }
        }
    }

    private static void waitForNode(BtqRpcClient rpc, Path cookie, Process process, Path log) throws Exception {
        Instant deadline = Instant.now().plusSeconds(45);
        Exception lastError = null;
        while(Instant.now().isBefore(deadline)) {
            if(!process.isAlive()) {
                fail("BTQ Core exited during startup. Log:\n" + Files.readString(log));
            }
            if(Files.isRegularFile(cookie)) {
                try {
                    rpc.callObject("getblockchaininfo");
                    return;
                } catch(Exception e) {
                    lastError = e;
                }
            }
            Thread.sleep(100);
        }
        fail("BTQ Core did not become ready: " + (lastError == null ? "no RPC response" : lastError.getMessage())
                + "\nLog:\n" + Files.readString(log));
    }

    private static int freePort() throws Exception {
        try(ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }
}
