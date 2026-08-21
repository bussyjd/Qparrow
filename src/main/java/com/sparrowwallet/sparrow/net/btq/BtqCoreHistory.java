package com.sparrowwallet.sparrow.net.btq;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.sparrowwallet.drongo.KeyPurpose;
import com.sparrowwallet.drongo.protocol.Script;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import com.sparrowwallet.drongo.protocol.Transaction;
import com.sparrowwallet.drongo.protocol.TransactionInput;
import com.sparrowwallet.drongo.protocol.TransactionOutput;
import com.sparrowwallet.drongo.wallet.BlockTransaction;
import com.sparrowwallet.drongo.wallet.BlockTransactionHashIndex;
import com.sparrowwallet.drongo.wallet.Wallet;
import com.sparrowwallet.drongo.wallet.WalletNode;
import javafx.concurrent.Service;
import javafx.concurrent.Task;

import java.util.Date;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Feeds a Bitcoin Quantum wallet's history from the BTQ Core watch-only wallet into the drongo wallet
 * model, mirroring the TXO and spent-link semantics of Sparrow's Electrum history flow so the
 * Transactions/Addresses/UTXOs tabs work unchanged.
 * <p>
 * v1 polls the full watch-wallet history ({@code listtransactions} + verbose {@code gettransaction})
 * on each refresh - custody wallet sizes make this cheap, and Core's watch wallet covers exactly the
 * registered P2MR addresses.
 */
public final class BtqCoreHistory {
    private static final HexFormat HEX = HexFormat.of();
    private static final int MAX_HISTORY_TRANSACTIONS = 1000;

    private BtqCoreHistory() {
    }

    /** Fetch the full watch-wallet history from Core and write it into the wallet model. Returns true if anything changed. */
    public static boolean updateWalletHistory(Wallet wallet, BtqRpcClient walletRpc) {
        //1. Collect the distinct transaction ids the watch wallet knows about
        JsonArray listed = walletRpc.callArray("listtransactions", "*", MAX_HISTORY_TRANSACTIONS, 0, true);
        Set<String> txids = new LinkedHashSet<>();
        for(JsonElement element : listed) {
            if(element.isJsonObject() && element.getAsJsonObject().has("txid")) {
                txids.add(element.getAsJsonObject().get("txid").getAsString());
            }
        }

        //2. Fetch each transaction verbosely and build the drongo BlockTransaction map
        Map<Sha256Hash, BlockTransaction> blockTransactions = new HashMap<>();
        for(String txid : txids) {
            JsonObject verbose = walletRpc.callObject("gettransaction", txid, true);
            if(!verbose.has("hex") || verbose.get("hex").isJsonNull()) {
                throw new IllegalStateException("gettransaction did not return hex for " + txid);
            }
            Transaction transaction = new Transaction(HEX.parseHex(verbose.get("hex").getAsString()));
            int height = verbose.has("blockheight") && !verbose.get("blockheight").isJsonNull()
                    ? verbose.get("blockheight").getAsInt() : 0;
            Date date = verbose.has("time") && !verbose.get("time").isJsonNull()
                    ? new Date(verbose.get("time").getAsLong() * 1000) : new Date();
            Long fee = null;
            if(verbose.has("fee") && !verbose.get("fee").isJsonNull()) {
                try {
                    fee = Math.abs(verbose.get("fee").getAsBigDecimal().movePointRight(8).longValueExact());
                } catch(Exception e) {
                    //fee display is optional; ignore malformed values
                }
            }
            Sha256Hash blockHash = verbose.has("blockhash") && !verbose.get("blockhash").isJsonNull()
                    ? Sha256Hash.wrap(verbose.get("blockhash").getAsString()) : null;
            blockTransactions.put(transaction.getTxId(),
                    new BlockTransaction(transaction.getTxId(), height, date, fee, transaction, blockHash));
        }

        boolean changed = false;
        if(!blockTransactions.isEmpty() && !wallet.getTransactions().keySet().containsAll(blockTransactions.keySet())) {
            changed = true;
        }
        wallet.updateTransactions(blockTransactions);

        //3. Rebuild each node's TXO set: received outputs first, then spent links, mirroring ElectrumServer
        for(KeyPurpose keyPurpose : KeyPurpose.DEFAULT_PURPOSES) {
            WalletNode purposeNode = wallet.getNode(keyPurpose);
            for(WalletNode node : purposeNode.getChildren()) {
                Script nodeScript = wallet.getOutputScript(node);
                if(nodeScript == null) {
                    //Locked wallet, uncached gap-window address: no funds can be here, skip
                    continue;
                }
                TreeSet<BlockTransactionHashIndex> transactionOutputs = new TreeSet<>();
                for(BlockTransaction blockTransaction : blockTransactions.values()) {
                    Transaction transaction = blockTransaction.getTransaction();
                    for(TransactionOutput output : transaction.getOutputs()) {
                        if(output.getScript().equals(nodeScript)) {
                            transactionOutputs.add(new BlockTransactionHashIndex(blockTransaction.getHash(),
                                    blockTransaction.getHeight(), blockTransaction.getDate(), blockTransaction.getFee(),
                                    output.getIndex(), output.getValue()));
                        }
                    }
                }
                for(BlockTransaction blockTransaction : blockTransactions.values()) {
                    Transaction transaction = blockTransaction.getTransaction();
                    for(int inputIndex = 0; inputIndex < transaction.getInputs().size(); inputIndex++) {
                        TransactionInput input = transaction.getInputs().get(inputIndex);
                        Sha256Hash previousHash = input.getOutpoint().getHash();
                        long previousIndex = input.getOutpoint().getIndex();
                        Optional<BlockTransactionHashIndex> optionalReceived = transactionOutputs.stream()
                                .filter(receivedTXO -> receivedTXO.getHash().equals(previousHash) && receivedTXO.getIndex() == previousIndex)
                                .findFirst();
                        if(optionalReceived.isPresent()) {
                            BlockTransactionHashIndex receivedTXO = optionalReceived.get();
                            BlockTransactionHashIndex spendingTXI = new BlockTransactionHashIndex(blockTransaction.getHash(),
                                    blockTransaction.getHeight(), blockTransaction.getDate(), blockTransaction.getFee(),
                                    inputIndex, receivedTXO.getValue());
                            receivedTXO.setSpentBy(spendingTXI);
                        }
                    }
                }
                if(!transactionOutputs.equals(node.getTransactionOutputs())) {
                    node.updateTransactionOutputs(wallet, transactionOutputs);
                    changed = true;
                }
            }
        }

        return changed;
    }

    /**
     * Ensure every derived wallet node is registered as watch-only P2MR metadata with Core - the node
     * cannot see funds arriving at an unregistered address. Registration is checked via getaddressinfo
     * first (Core-side idempotence), so this is safe to run on every refresh and covers gap extension.
     */
    public static void ensureAddressesRegistered(Wallet wallet, BtqWatchOnlyCore core) {
        com.sparrowwallet.drongo.Network network = core.network().toNetwork();
        com.sparrowwallet.drongo.wallet.Keystore keystore = wallet.getKeystores().get(0);
        for(KeyPurpose keyPurpose : KeyPurpose.DEFAULT_PURPOSES) {
            for(WalletNode node : wallet.getNode(keyPurpose).getChildren()) {
                byte[] mldsaPubKey = keystore.getBtqPublicKey(node);
                if(mldsaPubKey == null) {
                    //Locked wallet, uncached gap-window address: nothing has ever arrived here, skip
                    continue;
                }
                com.sparrowwallet.drongo.btq.P2MR.P2MRScript localScript =
                        com.sparrowwallet.drongo.btq.P2MR.scriptForPublicKey(network, mldsaPubKey);
                if(!core.isAddressRegistered(localScript.address())) {
                    core.registerAddress(localScript, keyPurpose, node.toString());
                }
            }
        }
    }

    /** JavaFX service wrapper: opens the configured Core connection, registers any new addresses, and refreshes the wallet's history. */
    public static class BtqHistoryService extends Service<Boolean> {
        private final Wallet wallet;

        public BtqHistoryService(Wallet wallet) {
            this.wallet = wallet;
        }

        @Override
        protected Task<Boolean> createTask() {
            return new Task<>() {
                @Override
                protected Boolean call() {
                    BtqNodeConfig nodeConfig = BtqConnection.fromConfig(
                            com.sparrowwallet.sparrow.io.Config.get(), com.sparrowwallet.drongo.Network.get());
                    try {
                        BtqRpcClient rpcClient = new BtqRpcClient(nodeConfig);
                        BtqWatchOnlyCore core = new BtqWatchOnlyCore(nodeConfig, rpcClient);
                        BtqWatchOnlyCore.NodeStatus status = core.verifyNode();
                        core.ensureWallet();
                        ensureAddressesRegistered(wallet, core);
                        //BTQ has no Electrum connection to supply the tip height; take it from Core so UTXO
                        //confirmations compute correctly (a zero stored height filters every UTXO out of coin selection)
                        wallet.setStoredBlockHeight(status.blocks());
                        return updateWalletHistory(wallet, rpcClient.wallet());
                    } finally {
                        nodeConfig.close();
                    }
                }
            };
        }
    }
}
