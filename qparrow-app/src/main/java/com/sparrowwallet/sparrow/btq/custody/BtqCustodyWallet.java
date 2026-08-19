// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import com.sparrowwallet.sparrow.btq.BtqNodeConfig;
import com.sparrowwallet.sparrow.btq.BtqP2mrAddressCodec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.HexFormat;

/** Lean application boundary joining the reviewed BTQ custody components. */
public final class BtqCustodyWallet implements AutoCloseable {
    private static final long MAX_MONEY_SATS = 21_000_000L * 100_000_000L;

    private final BtqNetwork network;
    private final Path vaultFile;
    private final Path stateFile;
    private final BtqWatchOnlyCore core;
    private final BtqWatchOnlyCore.NodeStatus nodeStatus;
    private final BtqWatchOnlyCore.WalletStatus walletStatus;
    private byte[] masterSecret;
    private byte[] authenticatedVault;

    private BtqCustodyWallet(BtqNetwork network, Path vaultFile, Path stateFile, BtqWatchOnlyCore core,
                             BtqWatchOnlyCore.NodeStatus nodeStatus,
                             BtqWatchOnlyCore.WalletStatus walletStatus, byte[] masterSecret,
                             byte[] authenticatedVault) {
        this.network = Objects.requireNonNull(network, "network");
        this.vaultFile = Objects.requireNonNull(vaultFile, "vaultFile").toAbsolutePath().normalize();
        this.stateFile = Objects.requireNonNull(stateFile, "stateFile").toAbsolutePath().normalize();
        this.core = Objects.requireNonNull(core, "core");
        this.nodeStatus = Objects.requireNonNull(nodeStatus, "nodeStatus");
        this.walletStatus = Objects.requireNonNull(walletStatus, "walletStatus");
        this.masterSecret = masterSecret;
        this.authenticatedVault = authenticatedVault;
    }

    /** Create only the strict Qparrow v1 vault; no seed or wallet import is accepted. */
    public static void create(Path vaultFile, Path stateFile, BtqNetwork network, char[] password,
                              SecureRandom random) throws IOException {
        Objects.requireNonNull(stateFile, "stateFile");
        if(Files.exists(stateFile.toAbsolutePath().normalize(), LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("refusing to attach a new vault to existing wallet state");
        }
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        random.nextBytes(master);
        boolean vaultCreated = false;
        try {
            BtqSeedVault.create(vaultFile, network, master, password, random);
            vaultCreated = true;
            BtqWalletStateStore.initializeNew(stateFile, master, network);
        } catch(IOException e) {
            if(vaultCreated) Files.deleteIfExists(vaultFile.toAbsolutePath().normalize());
            throw e;
        } finally {
            Arrays.fill(master, (byte)0);
        }
    }

    /** Open a wallet session and take ownership of the supplied node configuration and credentials. */
    public static BtqCustodyWallet open(Path vaultFile, Path stateFile, BtqNetwork network,
                                        char[] password, BtqNodeConfig nodeConfig) throws IOException {
        Objects.requireNonNull(nodeConfig, "nodeConfig");
        if(nodeConfig.network() != network) {
            nodeConfig.close();
            throw new IllegalArgumentException("vault and BTQ node networks must match");
        }
        boolean ownershipTransferred = false;
        try(BtqSeedVault.UnlockedSeed unlocked = BtqSeedVault.open(vaultFile, network, password)) {
            byte[] master = unlocked.copyMasterSecret();
            byte[] authenticatedVault = unlocked.copyAuthenticatedEncoding();
            BtqWatchOnlyCore core = null;
            try {
                BtqWalletStateStore.inspect(stateFile, master, network);
                String suffix = "-" + BtqWalletStateStore.walletIdHex(master, network);
                int maximumPrefix = 128 - suffix.length();
                String prefix = nodeConfig.walletName().substring(0,
                        Math.min(nodeConfig.walletName().length(), maximumPrefix));
                BtqNodeConfig boundNodeConfig = nodeConfig.withWalletName(prefix + suffix);
                core = new BtqWatchOnlyCore(boundNodeConfig);
                BtqWatchOnlyCore.NodeStatus nodeStatus = core.verifyNode();
                if(nodeStatus.initialBlockDownload()) {
                    throw new IOException("BTQ Core is still synchronizing; custody wallet remains locked until synchronization completes");
                }
                BtqWatchOnlyCore.WalletStatus walletStatus = core.ensureWallet();
                ownershipTransferred = true;
                return new BtqCustodyWallet(network, vaultFile, stateFile, core, nodeStatus, walletStatus,
                        master, authenticatedVault);
            } catch(IOException | RuntimeException e) {
                Arrays.fill(master, (byte)0);
                Arrays.fill(authenticatedVault, (byte)0);
                if(core != null) core.close();
                throw e;
            }
        } finally {
            if(!ownershipTransferred) nodeConfig.close();
        }
    }

    public BtqWatchOnlyCore.NodeStatus nodeStatus() {
        return nodeStatus;
    }

    public BtqWatchOnlyCore.WalletStatus walletStatus() {
        return walletStatus;
    }

    /** Export the encrypted vault and authenticated counters without exposing plaintext key material. */
    public synchronized void backup(Path target) throws IOException {
        ensureOpen();
        BtqCustodyBackup.write(vaultFile, authenticatedVault, stateFile, target, network, masterSecret);
    }

    /**
     * Recovery escape hatch: export one derivation's ML-DSA-44 secret key as a BTQ Core
     * Dilithium WIF, importable via {@code importdilithiumkey} to recover that single
     * address's funds without Qparrow. The returned string is raw secret key material.
     */
    public synchronized String exportDilithiumWif(BtqCustodySpec.Chain chain, int index) {
        ensureOpen();
        return BtqKeyExport.exportDilithiumWif(masterSecret, network, chain, index);
    }

    /** Reconstruct a lost Core watch wallet from authenticated local counters, then rescan from genesis. */
    public synchronized RecoveryResult recoverWatchState() throws IOException {
        ensureOpen();
        BtqWatchOnlyCore.NodeStatus currentNodeStatus = core.verifyNode();
        if(currentNodeStatus.initialBlockDownload()) {
            throw new IOException("BTQ Core is still synchronizing; recovery requires a fully synchronized node");
        }
        if(currentNodeStatus.pruned()) {
            throw new IOException("genesis recovery requires an unpruned BTQ Core node");
        }
        BtqWatchOnlyCore.WalletStatus recoveryWallet = core.ensureWallet();
        if(!walletStatus.name().equals(recoveryWallet.name())) {
            throw new IOException("BTQ Core recovery wallet namespace changed during this session");
        }
        BtqWalletStateStore.State state = BtqWalletStateStore.inspect(
                stateFile, masterSecret, network);
        int registered = 0;
        for(BtqCustodySpec.Chain chain : BtqCustodySpec.Chain.values()) {
            int limit = chain == BtqCustodySpec.Chain.RECEIVE ? state.nextReceive() : state.nextChange();
            for(int index = 0; index < limit; index++) {
                BtqP2mrKeyPath.Address address = BtqP2mrKeyPath.derive(masterSecret, network, chain, index);
                core.registerHistoricalAddress(address, "qparrow-recovery-" + chain.name().toLowerCase(
                        java.util.Locale.ROOT) + '-' + index);
                registered++;
            }
        }
        BtqWatchOnlyCore.RescanResult rescan = core.rescanFromGenesis();
        return new RecoveryResult(registered, rescan.startHeight(), rescan.stopHeight());
    }

    public static void restoreBackup(Path backup, Path vaultFile, Path stateFile, BtqNetwork network,
                                     char[] password) throws IOException {
        BtqCustodyBackup.restore(backup, vaultFile, stateFile, network, password);
    }

    /** Reserve durably, derive locally, then register only the public tree with Core. */
    public synchronized BtqP2mrKeyPath.Address nextAddress(BtqCustodySpec.Chain chain, String label)
            throws IOException {
        ensureOpen();
        int index = BtqWalletStateStore.reserveNext(stateFile, masterSecret, network, chain);
        BtqP2mrKeyPath.Address address = BtqP2mrKeyPath.derive(masterSecret, network, chain, index);
        core.registerAddress(address, label);
        return address;
    }

    /** Return only Core UTXOs that resolve to a durably reserved local derivation. */
    public synchronized List<Utxo> listUtxos(int minimumConfirmations) throws IOException {
        ensureOpen();
        List<Utxo> owned = new ArrayList<>();
        for(BtqWatchOnlyCore.WatchedUtxo watched : core.listUtxos(minimumConfirmations)) {
            owned.add(locateInput(watched));
        }
        return List.copyOf(owned);
    }

    private Utxo locateInput(BtqWatchOnlyCore.WatchedUtxo watched) throws IOException {
        String scriptPubKeyHex = watched.scriptPubKey();
        ensureOpen();
        if(scriptPubKeyHex == null || !scriptPubKeyHex.matches("[0-9a-fA-F]{68}")) {
            throw new IllegalArgumentException("UTXO scriptPubKey must be a 34-byte hexadecimal P2MR script");
        }
        byte[] script = HexFormat.of().parseHex(scriptPubKeyHex);
        BtqSpendIntent.requireP2mr(script, "UTXO script");
        BtqWalletStateStore.State state = BtqWalletStateStore.inspect(stateFile, masterSecret, network);
        for(BtqCustodySpec.Chain chain : BtqCustodySpec.Chain.values()) {
            int limit = chain == BtqCustodySpec.Chain.RECEIVE ? state.nextReceive() : state.nextChange();
            for(int index = 0; index < limit; index++) {
                if(Arrays.equals(script, BtqP2mrKeyPath.derive(masterSecret, network, chain, index).scriptPubKey())) {
                    return new Utxo(this,
                            new BtqPsbtSigner.Input(watched.txid(), watched.vout(), watched.amountSats(), chain, index), script,
                            watched.address(), watched.amountSats(), watched.confirmations());
                }
            }
        }
        throw new IllegalArgumentException("UTXO does not belong to any reserved Qparrow address");
    }

    /**
     * Construct an unsigned proposal. Calling this consumes a fresh change
     * index even when the proposal is later abandoned; gaps are intentional.
     */
    public synchronized PreparedSpend prepareSpend(List<Utxo> selectedInputs,
                                                    List<Payment> payments,
                                                    long feeRateSatsPerVbyte,
                                                    long maximumFeeSats) throws IOException {
        ensureOpen();
        Objects.requireNonNull(selectedInputs, "selectedInputs");
        Objects.requireNonNull(payments, "payments");
        if(selectedInputs.isEmpty() || payments.isEmpty()) {
            throw new IllegalArgumentException("at least one input and payment are required");
        }
        if(maximumFeeSats < 0 || maximumFeeSats > MAX_MONEY_SATS) {
            throw new IllegalArgumentException("maximum fee is outside the monetary range");
        }

        BtqP2mrKeyPath.Address change = nextAddress(BtqCustodySpec.Chain.CHANGE, "qparrow-change");
        List<BtqPsbtSigner.Input> approvedInputs = new ArrayList<>(selectedInputs.size());
        List<BtqWatchOnlyCore.Outpoint> outpoints = new ArrayList<>(selectedInputs.size());
        for(Utxo selectedInput : selectedInputs) {
            if(selectedInput == null || selectedInput.owner != this) {
                throw new IllegalArgumentException("selected input belongs to a different wallet session");
            }
            approvedInputs.add(selectedInput.input);
            outpoints.add(new BtqWatchOnlyCore.Outpoint(selectedInput.input.txid(), selectedInput.input.vout()));
        }
        List<BtqWatchOnlyCore.Payment> corePayments = payments.stream()
                .map(payment -> new BtqWatchOnlyCore.Payment(payment.address(), payment.amountSats()))
                .toList();
        BtqWatchOnlyCore.FundedPsbt funded = core.createFundedPsbt(
                outpoints, corePayments, change, feeRateSatsPerVbyte);
        if(funded.feeSats() > maximumFeeSats) {
            throw new IllegalArgumentException("BTQ Core funding fee exceeds the approved ceiling");
        }

        List<BtqSpendIntent.Payment> intentPayments = new ArrayList<>(payments.size());
        for(Payment payment : payments) {
            intentPayments.add(new BtqSpendIntent.Payment(
                    BtqP2mrAddressCodec.scriptPubKey(network, payment.address()), payment.amountSats()));
        }
        BtqSpendIntent intent = new BtqSpendIntent(intentPayments, change.scriptPubKey(), maximumFeeSats);
        return new PreparedSpend(this, funded, approvedInputs, payments, change, intent);
    }

    /** Reparse and validate the complete PSBT immediately before local signing. */
    public synchronized BtqPsbtSigner.SignedPsbt sign(PreparedSpend preparedSpend) {
        ensureOpen();
        Objects.requireNonNull(preparedSpend, "preparedSpend");
        if(preparedSpend.owner != this) {
            throw new IllegalArgumentException("spend proposal belongs to a different wallet session");
        }
        return BtqPsbtSigner.sign(preparedSpend.funded.base64(), masterSecret, network,
                preparedSpend.selectedInputs, preparedSpend.intent);
    }

    /** Validate the exact proposal locally before any user authorization or signature. */
    public synchronized BtqPsbtSigner.Review review(PreparedSpend preparedSpend) {
        ensureOpen();
        Objects.requireNonNull(preparedSpend, "preparedSpend");
        if(preparedSpend.owner != this) {
            throw new IllegalArgumentException("spend proposal belongs to a different wallet session");
        }
        return BtqPsbtSigner.review(preparedSpend.funded.base64(), masterSecret, network,
                preparedSpend.selectedInputs, preparedSpend.intent);
    }

    public synchronized BtqWatchOnlyCore.FinalizedTransaction finalize(BtqPsbtSigner.SignedPsbt signedPsbt) {
        ensureOpen();
        return core.finalizeSignedPsbt(signedPsbt);
    }

    public synchronized BtqWatchOnlyCore.BroadcastResult broadcast(
            BtqWatchOnlyCore.FinalizedTransaction finalizedTransaction) {
        ensureOpen();
        return core.broadcast(finalizedTransaction);
    }

    private void ensureOpen() {
        if(masterSecret == null) throw new IllegalStateException("custody wallet is locked");
    }

    @Override
    public synchronized void close() {
        if(masterSecret != null) {
            Arrays.fill(masterSecret, (byte)0);
            masterSecret = null;
        }
        if(authenticatedVault != null) {
            Arrays.fill(authenticatedVault, (byte)0);
            authenticatedVault = null;
        }
        core.close();
    }

    public record Payment(String address, long amountSats) {
        public Payment {
            if(address == null || address.isBlank()) throw new IllegalArgumentException("payment address is required");
            if(amountSats <= 0 || amountSats > MAX_MONEY_SATS) {
                throw new IllegalArgumentException("payment amount is outside the monetary range");
            }
        }
    }

    public record RecoveryResult(int registeredAddresses, int startHeight, int stopHeight) {
    }

    public static final class Utxo {
        private final BtqCustodyWallet owner;
        private final BtqPsbtSigner.Input input;
        private final byte[] scriptPubKey;
        private final String address;
        private final long amountSats;
        private final int confirmations;

        private Utxo(BtqCustodyWallet owner, BtqPsbtSigner.Input input, byte[] scriptPubKey,
                     String address, long amountSats, int confirmations) {
            this.owner = owner;
            this.input = input;
            this.scriptPubKey = scriptPubKey.clone();
            this.address = address;
            this.amountSats = amountSats;
            this.confirmations = confirmations;
        }

        public BtqPsbtSigner.Input input() {
            return input;
        }

        public byte[] scriptPubKey() {
            return scriptPubKey.clone();
        }

        public String address() {
            return address;
        }

        public long amountSats() {
            return amountSats;
        }

        public int confirmations() {
            return confirmations;
        }

        public String outpoint() {
            return input.txid() + ':' + input.vout();
        }
    }

    public static final class PreparedSpend {
        private final BtqCustodyWallet owner;
        private final BtqWatchOnlyCore.FundedPsbt funded;
        private final List<BtqPsbtSigner.Input> selectedInputs;
        private final List<Payment> payments;
        private final BtqP2mrKeyPath.Address change;
        private final BtqSpendIntent intent;

        private PreparedSpend(BtqCustodyWallet owner, BtqWatchOnlyCore.FundedPsbt funded,
                              List<BtqPsbtSigner.Input> selectedInputs, List<Payment> payments,
                              BtqP2mrKeyPath.Address change, BtqSpendIntent intent) {
            this.owner = owner;
            this.funded = funded;
            this.selectedInputs = List.copyOf(selectedInputs);
            this.payments = List.copyOf(payments);
            this.change = change;
            this.intent = intent;
        }

        public BtqWatchOnlyCore.FundedPsbt funded() {
            return funded;
        }

        public List<BtqPsbtSigner.Input> selectedInputs() {
            return selectedInputs;
        }

        public List<Payment> payments() {
            return payments;
        }

        public BtqP2mrKeyPath.Address change() {
            return change;
        }
    }
}
