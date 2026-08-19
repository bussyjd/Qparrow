// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sparrowwallet.sparrow.btq.custody.BtqCustodySpec;
import com.sparrowwallet.sparrow.btq.custody.BtqCustodyWallet;
import com.sparrowwallet.sparrow.btq.custody.BtqP2mrKeyPath;
import com.sparrowwallet.sparrow.btq.custody.BtqPsbtSigner;
import com.sparrowwallet.sparrow.btq.custody.BtqWatchOnlyCore;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigDecimal;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.Comparator;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Real-process custody proof against the exact BTQ Core binary under test. */
@Tag("btq-integration")
class BtqCoreRegtestIntegrationTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void localCustodySurvivesRestartAndBroadcastsAValidatedMldsaP2mrSpend() throws Exception {
        String binarySetting = System.getenv("BTQ_CORE_BIN");
        assumeTrue(binarySetting != null && !binarySetting.isBlank(),
                "Set BTQ_CORE_BIN to run the real BTQ Core integration test");
        Path binary = Path.of(binarySetting).toAbsolutePath();
        assumeTrue(Files.isExecutable(binary), "BTQ_CORE_BIN is not executable: " + binary);

        Path dataDirectory = temporaryDirectory.resolve("node");
        Files.createDirectories(dataDirectory);
        int rpcPort = freePort();
        int p2pPort = freePort();
        Path log = temporaryDirectory.resolve("btqd.log");
        ProcessBuilder nodeBuilder = new ProcessBuilder(binary.toString(), "-regtest", "-datadir=" + dataDirectory,
                "-server=1", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                "-rpcport=" + rpcPort, "-port=" + p2pPort, "-listen=0", "-dnsseed=0",
                "-discover=0", "-fallbackfee=0.00001", "-printtoconsole=1")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.appendTo(log.toFile()));
        Process process = nodeBuilder.start();

        Path cookie = dataDirectory.resolve("regtest").resolve(".cookie");
        BtqNodeConfig nodeConfig = new BtqNodeConfig(java.net.URI.create("http://127.0.0.1:" + rpcPort + "/"),
                "qparrow_custody_e2e", BtqNetwork.REGTEST, BtqRpcCredentials.cookie(cookie), Duration.ofSeconds(60));
        BtqNodeConfig minerConfig = new BtqNodeConfig(nodeConfig.rpcUri(), "miner_e2e", BtqNetwork.REGTEST,
                BtqRpcCredentials.cookie(cookie), Duration.ofSeconds(60));
        BtqRpcClient nodeRpc = new BtqRpcClient(nodeConfig).node();
        char[] password = "integration-only-password".toCharArray();
        Path vault = temporaryDirectory.resolve("custody.qpbtq");
        Path state = temporaryDirectory.resolve("custody.qpstate");
        String boundWatchWalletName = null;
        try {
            waitForNode(nodeRpc, cookie, process, log);
            nodeRpc.call("createwallet", minerConfig.walletName(), false, false, "", false, true, true, false);
            BtqRpcClient minerRpc = new BtqRpcClient(minerConfig).wallet();
            String miningAddress = minerRpc.callString("getnewaddress", "mining", "bech32");
            nodeRpc.callArray("generatetoaddress", 101, miningAddress);

            BtqCustodyWallet.create(vault, state, BtqNetwork.REGTEST, password, new SecureRandom());
            String broadcastTxid;
            try(BtqCustodyWallet wallet = BtqCustodyWallet.open(
                    vault, state, BtqNetwork.REGTEST, password, nodeConfig)) {
                assertEquals(BtqNetwork.REGTEST, wallet.nodeStatus().network());
                assertTrue(wallet.nodeStatus().subversion().toLowerCase().contains("btq"));
                assertTrue(wallet.walletStatus().descriptors());
                assertFalse(wallet.walletStatus().privateKeysEnabled());
                assertTrue(wallet.walletStatus().blank());
                boundWatchWalletName = wallet.walletStatus().name();
                assertTrue(boundWatchWalletName.startsWith(nodeConfig.walletName() + "-"));

                BtqP2mrKeyPath.Address source = wallet.nextAddress(BtqCustodySpec.Chain.RECEIVE, "source-0");
                BtqP2mrKeyPath.Address secondSource = wallet.nextAddress(
                        BtqCustodySpec.Chain.RECEIVE, "source-1");
                BtqP2mrKeyPath.Address recipient = wallet.nextAddress(BtqCustodySpec.Chain.RECEIVE, "recipient");

                // Recovery escape hatch: the exported Dilithium WIF must re-derive the SAME
                // P2MR address inside BTQ Core via importdilithiumkey (funds recoverable
                // without Qparrow). Verified against the real binary under test.
                String receiveWif = wallet.exportDilithiumWif(BtqCustodySpec.Chain.RECEIVE, source.index());
                nodeRpc.call("createwallet", "rescue_e2e", false, false, "", false, true, true, false);
                BtqNodeConfig rescueConfig = new BtqNodeConfig(nodeConfig.rpcUri(), "rescue_e2e",
                        BtqNetwork.REGTEST, BtqRpcCredentials.cookie(cookie), Duration.ofSeconds(60));
                BtqRpcClient rescueRpc = new BtqRpcClient(rescueConfig).wallet();
                JsonObject imported = rescueRpc.callObject("importdilithiumkey", receiveWif, "rescued", false);
                assertEquals(source.address(), imported.get("address").getAsString(),
                        "exported WIF must re-derive the same P2MR address in BTQ Core");
                JsonObject rescuedInfo = rescueRpc.callObject("getaddressinfo", source.address());
                assertTrue(rescuedInfo.get("ismine").getAsBoolean(),
                        "rescued wallet must own the imported P2MR address");
                minerRpc.callString("sendtoaddress", source.address(), new BigDecimal("0.15"));
                minerRpc.callString("sendtoaddress", secondSource.address(), new BigDecimal("0.15"));
                nodeRpc.callArray("generatetoaddress", 1, miningAddress);
                nodeRpc.call("syncwithvalidationinterfacequeue");

                List<BtqCustodyWallet.Utxo> unspent = wallet.listUtxos(1);
                assertEquals(2, unspent.size());
                assertEquals(30_000_000L, unspent.stream().mapToLong(BtqCustodyWallet.Utxo::amountSats).sum());
                assertEquals(List.of(0, 1), unspent.stream().map(utxo -> utxo.input().index()).sorted().toList());
                assertTrue(unspent.stream().allMatch(utxo ->
                        utxo.input().chain() == BtqCustodySpec.Chain.RECEIVE));

                BtqCustodyWallet.PreparedSpend prepared = wallet.prepareSpend(unspent,
                        List.of(new BtqCustodyWallet.Payment(recipient.address(), 10_000_000)), 1, 100_000);
                BtqPsbtSigner.SignedPsbt signed = wallet.sign(prepared);
                BtqWatchOnlyCore.FinalizedTransaction finalized = wallet.finalize(signed);
                assertEquals(64, finalized.txid().length());

                JsonObject decoded = nodeRpc.callObject("decoderawtransaction", finalized.hex());
                assertEquals(finalized.txid(), decoded.get("txid").getAsString());
                assertEquals(finalized.wtxid(), decoded.get("hash").getAsString());
                JsonArray inputs = decoded.getAsJsonArray("vin");
                assertEquals(2, inputs.size());
                String signature = null;
                for(JsonElement input : inputs) {
                    JsonArray witness = input.getAsJsonObject().getAsJsonArray("txinwitness");
                    assertEquals(3, witness.size(), "P2MR witness must contain signature, leaf, and control block");
                    assertEquals(2 * BtqMldsaSignatureBytes.TX_SIGNATURE_BYTES,
                            witness.get(0).getAsString().length());
                    assertEquals(2 * (1312 + 4), witness.get(1).getAsString().length());
                    assertTrue(witness.get(1).getAsString().startsWith("4d2005"),
                            "P2MR leaf must contain the 1312-byte ML-DSA public key");
                    assertEquals(2, witness.get(2).getAsString().length());
                    if(signature == null) {
                        signature = witness.get(0).getAsString();
                    }
                }
                assertNotNull(signature);

                int signatureOffset = finalized.hex().indexOf(signature);
                int mutationOffset = signatureOffset + 200;
                String oldByte = finalized.hex().substring(mutationOffset, mutationOffset + 2);
                String tampered = finalized.hex().substring(0, mutationOffset)
                        + (oldByte.equals("00") ? "01" : "00") + finalized.hex().substring(mutationOffset + 2);
                JsonArray rejection = nodeRpc.callArray("testmempoolaccept", List.of(tampered));
                assertFalse(rejection.get(0).getAsJsonObject().get("allowed").getAsBoolean());

                BtqWatchOnlyCore.BroadcastResult broadcast = wallet.broadcast(finalized);
                assertEquals(finalized.txid(), broadcast.txid());
                broadcastTxid = broadcast.txid();
                nodeRpc.callArray("generatetoaddress", 1, miningAddress);
                nodeRpc.call("syncwithvalidationinterfacequeue");
            }

            // First prove the existing Core watch wallet loads and retains its
            // metadata across an ordinary node restart.
            nodeRpc.call("stop");
            assertTrue(process.waitFor(15, TimeUnit.SECONDS));
            process = nodeBuilder.start();
            waitForNode(nodeRpc, cookie, process, log);
            try(BtqCustodyWallet persisted = BtqCustodyWallet.open(
                    vault, state, BtqNetwork.REGTEST, password, nodeConfig)) {
                assertEquals(boundWatchWalletName, persisted.walletStatus().name());
                assertEquals(2, persisted.listUtxos(1).size());
                nodeRpc.call("unloadwallet", boundWatchWalletName, false);
                assertEquals(4, persisted.recoverWatchState().registeredAddresses());
                assertEquals(2, persisted.listUtxos(1).size());
            }
            nodeRpc.call("unloadwallet", boundWatchWalletName, false);
            try(BtqCustodyWallet explicitlyLoaded = BtqCustodyWallet.open(
                    vault, state, BtqNetwork.REGTEST, password, nodeConfig)) {
                assertEquals(boundWatchWalletName, explicitlyLoaded.walletStatus().name());
                assertEquals(2, explicitlyLoaded.listUtxos(1).size());
            }

            // Then simulate complete loss of Core's public watch wallet while
            // preserving Qparrow custody files.
            nodeRpc.call("stop");
            assertTrue(process.waitFor(15, TimeUnit.SECONDS));
            Path coreWatchWallet = dataDirectory.resolve("regtest").resolve("wallets")
                    .resolve(boundWatchWalletName);
            assertTrue(Files.isDirectory(coreWatchWallet), "expected Core watch wallet directory");
            deleteTree(coreWatchWallet);
            process = nodeBuilder.start();
            waitForNode(nodeRpc, cookie, process, log);

            try(BtqCustodyWallet reopened = BtqCustodyWallet.open(
                    vault, state, BtqNetwork.REGTEST, password, nodeConfig)) {
                BtqCustodyWallet.RecoveryResult recovery = reopened.recoverWatchState();
                assertEquals(4, recovery.registeredAddresses());
                assertEquals(0, recovery.startHeight());
                List<BtqCustodyWallet.Utxo> afterRestart = reopened.listUtxos(1);
                assertEquals(2, afterRestart.size(), "recipient and quantum change remain locally owned");
                BtqP2mrKeyPath.Address next = reopened.nextAddress(BtqCustodySpec.Chain.RECEIVE, "after-restart");
                assertEquals(3, next.index());
                JsonObject transaction = new BtqRpcClient(nodeConfig.withWalletName(boundWatchWalletName)).wallet()
                        .callObject("gettransaction", broadcastTxid, true, true);
                assertTrue(transaction.get("confirmations").getAsInt() > 0);
            }
        } finally {
            Arrays.fill(password, '\0');
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
            if(!process.isAlive()) fail("BTQ Core exited during startup. Log:\n" + Files.readString(log));
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

    private static void deleteTree(Path root) throws Exception {
        try(var paths = Files.walk(root)) {
            for(Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        }
    }

    /** Keeps the protocol assertion named without exposing signer internals to the integration package. */
    private static final class BtqMldsaSignatureBytes {
        private static final int TX_SIGNATURE_BYTES = 2421;
    }
}
