// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow;

import com.sparrowwallet.sparrow.btq.BtqAuthMode;
import com.sparrowwallet.sparrow.btq.BtqNetwork;
import com.sparrowwallet.sparrow.btq.BtqNodeProfile;
import com.sparrowwallet.sparrow.btq.BtqNodeProfileStore;
import com.sparrowwallet.sparrow.btq.BtqP2mrAddressCodec;
import com.sparrowwallet.sparrow.btq.custody.BtqCustodySpec;
import com.sparrowwallet.sparrow.btq.custody.BtqCustodyWallet;
import com.sparrowwallet.sparrow.btq.custody.BtqP2mrKeyPath;
import com.sparrowwallet.sparrow.btq.custody.BtqPsbtSigner;
import com.sparrowwallet.sparrow.btq.custody.BtqWatchOnlyCore;
import javafx.animation.PauseTransition;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.SelectionMode;
import javafx.scene.control.Separator;
import javafx.scene.control.TextField;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.stage.FileChooser;
import javafx.util.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.CompletionException;
import java.util.function.Consumer;

/** Lean BTQ-only UI. Qparrow owns ML-DSA keys; BTQ Core is public watch state and transport. */
public final class QparrowDesktop extends Application {
    private static final Logger LOG = LoggerFactory.getLogger(QparrowDesktop.class);
    private static final String WINDOW_STYLE = "-fx-font-family: system; -fx-font-size: 13px; -fx-background-color: #11151b;";
    private static final String CARD_STYLE = "-fx-background-color: #1b222c; -fx-background-radius: 10; -fx-padding: 18;";
    private static final String HEADING_STYLE = "-fx-font-size: 19px; -fx-font-weight: bold; -fx-text-fill: #f4f7fb;";
    private static final String MUTED_STYLE = "-fx-text-fill: #9aa7b6;";
    private static final String VALUE_STYLE = "-fx-text-fill: #f4f7fb; -fx-font-family: monospace;";
    private static final java.time.Duration RPC_TIMEOUT = java.time.Duration.ofSeconds(30);
    private static final Duration SESSION_TIMEOUT = Duration.minutes(10);

    private final ExecutorService worker = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "qparrow-custody");
        thread.setDaemon(true);
        return thread;
    });
    private final PauseTransition sessionTimer = new PauseTransition(SESSION_TIMEOUT);

    private final ComboBox<BtqNetwork> network = new ComboBox<>();
    private final TextField rpcUri = new TextField();
    private final TextField walletName = new TextField("qparrow-custody");
    private final ComboBox<BtqAuthMode> authMode = new ComboBox<>();
    private final TextField cookieFile = new TextField();
    private final TextField rpcUsername = new TextField();
    private final PasswordField rpcPassword = new PasswordField();
    private final PasswordField vaultPassword = new PasswordField();
    private final PasswordField vaultConfirmation = new PasswordField();
    private final Button createWallet = new Button("Create new custody wallet");
    private final Button backupWallet = new Button("Back up");
    private final Button restoreWallet = new Button("Restore");
    private final Button recoverWatch = new Button("Rebuild Core watch");
    private final Button unlock = new Button("Unlock and connect");
    private final Button lock = new Button("Lock");
    private final Label status = mutedLabel("Locked");
    private final Label vaultPath = valueLabel("-");

    private final Label nodeStatus = valueLabel("-");
    private final Label balance = valueLabel("0 BTQ");
    private final Label balanceDetail = mutedLabel("0 confirmed · 0 pending · 0 UTXOs");
    private final ListView<BtqCustodyWallet.Utxo> utxos = new ListView<>();
    private final Button refresh = new Button("Refresh");
    private final TextField receiveLabel = new TextField();
    private final Label latestAddress = valueLabel("No receive address reserved yet");
    private final Button newAddress = new Button("Reserve receive address");
    private final Button copyAddress = new Button("Copy");
    private final TextField destination = new TextField();
    private final TextField amount = new TextField();
    private final TextField feeRate = new TextField("1");
    private final TextField maximumFee = new TextField("0.001");
    private final Button reviewSpend = new Button("Review, sign, and broadcast");

    private BtqNodeProfileStore profileStore;
    private Stage stage;
    private volatile BtqCustodyWallet wallet;
    private volatile BtqNetwork connectedNetwork;
    private boolean operationRunning;
    private static volatile BtqNetwork initialNetwork = BtqNetwork.REGTEST;

    public static void setInitialNetwork(BtqNetwork value) {
        initialNetwork = value;
    }

    @Override
    public void start(Stage stage) throws Exception {
        this.stage = stage;
        Files.createDirectories(QparrowPaths.configHome());
        profileStore = new BtqNodeProfileStore(QparrowPaths.configHome());
        configureFields();
        loadProfile();
        sessionTimer.setOnFinished(event -> lockSession("Wallet locked after 10 minutes of inactivity"));

        BorderPane root = new BorderPane();
        root.setPadding(new Insets(20));
        root.setStyle(WINDOW_STYLE);
        root.setTop(header());
        ScrollPane scroll = new ScrollPane(content());
        scroll.setFitToWidth(true);
        scroll.setStyle("-fx-background-color: transparent; -fx-background: transparent;");
        root.setCenter(scroll);

        stage.setTitle(QparrowLauncher.APP_NAME + " — Bitcoin Quantum custody");
        stage.setMinWidth(880);
        stage.setMinHeight(720);
        stage.setScene(new Scene(root, 1040, 820));
        stage.show();
        updatePaths();
        setConnectionControlsDisabled(false);
        setWalletControlsDisabled(true);
    }

    private VBox header() {
        Label title = new Label("Qparrow");
        title.setStyle("-fx-font-size: 28px; -fx-font-weight: bold; -fx-text-fill: #64e6c4;");
        Label subtitle = mutedLabel("Local ML-DSA custody · P2MR only · BTQ Core watch-only");
        VBox box = new VBox(4, title, subtitle, new Separator());
        box.setPadding(new Insets(0, 0, 16, 0));
        return box;
    }

    private HBox content() {
        VBox connection = connectionCard();
        VBox walletView = walletCard();
        connection.setMaxWidth(Double.MAX_VALUE);
        walletView.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(connection, Priority.ALWAYS);
        HBox.setHgrow(walletView, Priority.ALWAYS);
        return new HBox(16, connection, walletView);
    }

    private VBox connectionCard() {
        Label heading = heading("Custody and BTQ Core");
        Label explanation = mutedLabel("The encrypted vault and signatures remain in Qparrow. Core receives only public P2MR trees and runs a private-key-disabled descriptor wallet.");
        explanation.setWrapText(true);
        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(9);
        addRow(grid, 0, "Network", network);
        addRow(grid, 1, "RPC URI", rpcUri);
        addRow(grid, 2, "Watch wallet", walletName);
        addRow(grid, 3, "Authentication", authMode);
        addRow(grid, 4, "Cookie file", cookieFile);
        addRow(grid, 5, "RPC username", rpcUsername);
        addRow(grid, 6, "RPC password", rpcPassword);
        addRow(grid, 7, "Vault password", vaultPassword);
        addRow(grid, 8, "Confirm (create)", vaultConfirmation);

        vaultPath.setWrapText(true);
        HBox buttons = new HBox(8, createWallet, unlock, lock);
        HBox recoveryButtons = new HBox(8, backupWallet, restoreWallet, recoverWatch);
        createWallet.setOnAction(event -> createWallet());
        backupWallet.setOnAction(event -> backupWallet());
        restoreWallet.setOnAction(event -> restoreWallet());
        recoverWatch.setOnAction(event -> recoverWatchState());
        unlock.setOnAction(event -> unlockWallet());
        lock.setOnAction(event -> lockSession("Wallet locked"));
        lock.setDisable(true);
        status.setWrapText(true);
        VBox card = new VBox(11, heading, explanation, grid, mutedLabel("Encrypted vault"), vaultPath,
                buttons, recoveryButtons, status);
        card.setStyle(CARD_STYLE);
        card.setPrefWidth(470);
        return card;
    }

    private VBox walletCard() {
        Label heading = heading("Wallet");
        nodeStatus.setWrapText(true);
        balance.setStyle("-fx-font-size: 24px; -fx-font-weight: bold; -fx-text-fill: #f4f7fb;");
        refresh.setOnAction(event -> refreshWallet());
        HBox balanceLine = new HBox(10, balance, refresh);
        balanceLine.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(balance, Priority.ALWAYS);

        utxos.getSelectionModel().setSelectionMode(SelectionMode.MULTIPLE);
        utxos.setPrefHeight(150);
        utxos.setPlaceholder(new Label("No locally owned P2MR outputs"));
        utxos.setCellFactory(view -> new ListCell<>() {
            @Override
            protected void updateItem(BtqCustodyWallet.Utxo item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : formatSats(item.amountSats()) + " BTQ · "
                        + item.confirmations() + " conf · " + abbreviate(item.outpoint()));
            }
        });

        receiveLabel.setPromptText("Optional public label");
        newAddress.setOnAction(event -> reserveReceiveAddress());
        copyAddress.setOnAction(event -> copyReceiveAddress());
        latestAddress.setWrapText(true);
        HBox receiveActions = new HBox(8, receiveLabel, newAddress);
        HBox.setHgrow(receiveLabel, Priority.ALWAYS);
        HBox addressLine = new HBox(8, latestAddress, copyAddress);
        HBox.setHgrow(latestAddress, Priority.ALWAYS);

        destination.setPromptText("Same-network BTQ P2MR address");
        amount.setPromptText("BTQ, up to 8 decimals");
        GridPane spend = new GridPane();
        spend.setHgap(8);
        spend.setVgap(8);
        addRow(spend, 0, "Destination", destination);
        addRow(spend, 1, "Amount BTQ", amount);
        addRow(spend, 2, "Fee rate sat/vB", feeRate);
        addRow(spend, 3, "Maximum fee BTQ", maximumFee);
        reviewSpend.setMaxWidth(Double.MAX_VALUE);
        reviewSpend.setOnAction(event -> prepareSpend());

        VBox card = new VBox(11, heading, nodeStatus, balanceLine, balanceDetail,
                section("Spendable P2MR UTXOs (select one or more)"), utxos,
                section("Receive"), receiveActions, addressLine,
                section("Send"), spend, reviewSpend);
        card.setStyle(CARD_STYLE);
        card.setPrefWidth(510);
        return card;
    }

    private void configureFields() {
        network.getItems().setAll(BtqNetwork.values());
        network.setValue(initialNetwork);
        authMode.getItems().setAll(BtqAuthMode.values());
        authMode.setValue(BtqAuthMode.COOKIE);
        rpcUri.setText(defaultRpcUri(initialNetwork));
        cookieFile.setText(defaultCookieFile(initialNetwork).toString());
        network.valueProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue != null && wallet == null) {
                rpcUri.setText(defaultRpcUri(newValue));
                cookieFile.setText(defaultCookieFile(newValue).toString());
                updatePaths();
            }
        });
        authMode.valueProperty().addListener((observable, oldValue, newValue) -> updateAuthFields());
        updateAuthFields();
    }

    private void loadProfile() {
        try {
            Optional<BtqNodeProfile> stored = profileStore.load();
            if(stored.isEmpty()) return;
            BtqNodeProfile profile = stored.get();
            network.setValue(profile.network());
            rpcUri.setText(profile.rpcUri().toString());
            walletName.setText(profile.walletName());
            authMode.setValue(profile.authMode());
            rpcUsername.setText(profile.rpcUsername());
            if(profile.cookieFile() != null) cookieFile.setText(profile.cookieFile().toString());
        } catch(Exception e) {
            status.setText("Stored public node profile rejected: " + safeMessage(e));
        }
    }

    private void createWallet() {
        if(wallet != null) return;
        char[] password = vaultPassword.getText().toCharArray();
        char[] confirmation = vaultConfirmation.getText().toCharArray();
        BtqNetwork selected = network.getValue();
        if(!Arrays.equals(password, confirmation)) {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
            showError("Could not create custody wallet",
                    new IllegalArgumentException("vault password confirmation does not match"));
            return;
        }
        vaultConfirmation.clear();
        runOperation("Deriving encryption key and creating custody vault…", () -> {
            try {
                Files.createDirectories(QparrowPaths.configHome());
                BtqCustodyWallet.create(QparrowPaths.vault(selected), QparrowPaths.state(selected),
                        selected, password, new SecureRandom());
                return selected;
            } finally {
                Arrays.fill(password, '\0');
                Arrays.fill(confirmation, '\0');
            }
        }, createdNetwork -> {
            vaultPassword.clear();
            status.setText("New encrypted vault created. Unlock, reserve an address, then create a backup.");
            showInformation("Custody vault created", "Qparrow created a new encrypted " + createdNetwork
                    + " vault at:\n" + QparrowPaths.vault(createdNetwork)
                    + "\n\nThere is no compatibility/import path. Losing the backup or password loses custody.");
        });
    }

    private void backupWallet() {
        BtqCustodyWallet current = requireWallet();
        if(current == null) return;
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Create encrypted Qparrow custody backup");
        chooser.setInitialFileName(connectedNetwork.name().toLowerCase(java.util.Locale.ROOT) + ".qpbackup");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Qparrow backup", "*.qpbackup"));
        java.io.File selected = chooser.showSaveDialog(stage);
        if(selected == null) return;
        Path target = selected.toPath();
        runOperation("Writing encrypted custody backup…", () -> {
            current.backup(target);
            return target;
        }, written -> showInformation("Backup created", "Encrypted vault and authenticated address counters:\n"
                + written + "\n\nKeep the newest backup offline. Older counter snapshots can cause address reuse."));
    }

    private void restoreWallet() {
        if(wallet != null) return;
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Restore Qparrow custody backup");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Qparrow backup", "*.qpbackup"));
        java.io.File selected = chooser.showOpenDialog(stage);
        if(selected == null) return;
        BtqNetwork selectedNetwork = network.getValue();
        char[] password = vaultPassword.getText().toCharArray();
        runOperation("Authenticating and restoring custody backup…", () -> {
            try {
                BtqCustodyWallet.restoreBackup(selected.toPath(), QparrowPaths.vault(selectedNetwork),
                        QparrowPaths.state(selectedNetwork), selectedNetwork, password);
                return selectedNetwork;
            } finally {
                Arrays.fill(password, '\0');
            }
        }, restoredNetwork -> {
            vaultPassword.clear();
            status.setText("Restored authenticated " + restoredNetwork + " custody files; unlock to verify Core watch state");
        });
    }

    private void recoverWatchState() {
        BtqCustodyWallet current = requireWallet();
        if(current == null) return;
        Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION);
        confirmation.setTitle("Rebuild BTQ Core watch state");
        confirmation.setHeaderText("Register all reserved public addresses and rescan from genesis?");
        confirmation.setContentText("Use this after restoring a backup or losing Core's watch-only wallet. "
                + "No private key is sent to Core. A full rescan can take a long time.");
        if(confirmation.showAndWait().filter(ButtonType.OK::equals).isEmpty()) return;
        runOperation("Rebuilding public P2MR metadata and rescanning…", current::recoverWatchState, recovered -> {
            status.setText("Recovered " + recovered.registeredAddresses() + " public derivations through block "
                    + recovered.stopHeight());
            refreshWallet();
        });
    }

    private void unlockWallet() {
        if(wallet != null) return;
        final BtqNodeProfile profile;
        try {
            profile = profileFromFields();
        } catch(Exception e) {
            showError("Invalid connection settings", e);
            return;
        }
        char[] custodyPassword = vaultPassword.getText().toCharArray();
        char[] nodePassword = rpcPassword.getText().toCharArray();
        runOperation("Verifying BTQ Core and unlocking local custody…", () -> {
            try {
                return BtqCustodyWallet.open(QparrowPaths.vault(profile.network()),
                        QparrowPaths.state(profile.network()), profile.network(), custodyPassword,
                        profile.toConfig(nodePassword));
            } finally {
                Arrays.fill(custodyPassword, '\0');
                Arrays.fill(nodePassword, '\0');
            }
        }, candidate -> {
            wallet = candidate;
            connectedNetwork = profile.network();
            try {
                profileStore.save(profile);
            } catch(Exception e) {
                lockSession("Wallet locked because the public node profile could not be saved");
                showError("Could not save public node profile", e);
                return;
            }
            rpcPassword.clear();
            vaultPassword.clear();
            vaultConfirmation.clear();
            BtqWatchOnlyCore.NodeStatus node = candidate.nodeStatus();
            nodeStatus.setText(node.subversion() + " · " + node.network() + " · " + node.blocks()
                    + "/" + node.headers() + (node.initialBlockDownload() ? " · syncing" : ""));
            setConnectionControlsDisabled(true);
            setWalletControlsDisabled(false);
            lock.setDisable(false);
            resetSessionTimer();
            refreshWallet();
        });
    }

    private void refreshWallet() {
        BtqCustodyWallet current = requireWallet();
        if(current == null) return;
        resetSessionTimer();
        runOperation("Validating watch-only UTXOs…", () -> current.listUtxos(0), entries -> {
            long confirmed = entries.stream().filter(entry -> entry.confirmations() > 0)
                    .mapToLong(BtqCustodyWallet.Utxo::amountSats).sum();
            long pending = entries.stream().filter(entry -> entry.confirmations() == 0)
                    .mapToLong(BtqCustodyWallet.Utxo::amountSats).sum();
            balance.setText(formatSats(Math.addExact(confirmed, pending)) + " BTQ");
            balanceDetail.setText(formatSats(confirmed) + " confirmed · " + formatSats(pending)
                    + " pending · " + entries.size() + " P2MR UTXOs");
            utxos.getItems().setAll(entries);
        });
    }

    private void reserveReceiveAddress() {
        BtqCustodyWallet current = requireWallet();
        if(current == null) return;
        resetSessionTimer();
        runOperation("Reserving address before display…", () -> current.nextAddress(
                BtqCustodySpec.Chain.RECEIVE, receiveLabel.getText().trim()), address -> {
            latestAddress.setText(address.address());
            receiveLabel.clear();
            status.setText("Receive address reserved durably and registered watch-only");
        });
    }

    private void prepareSpend() {
        BtqCustodyWallet current = requireWallet();
        if(current == null) return;
        resetSessionTimer();
        List<BtqCustodyWallet.Utxo> selected = List.copyOf(utxos.getSelectionModel().getSelectedItems());
        if(selected.isEmpty()) {
            showError("No inputs selected", new IllegalArgumentException("select one or more P2MR UTXOs"));
            return;
        }
        final String address = destination.getText().trim();
        final long amountSats;
        final long maximumFeeSats;
        final long feeRateSats;
        try {
            if(!BtqP2mrAddressCodec.isCanonicalAddress(connectedNetwork, address)) {
                throw new IllegalArgumentException("destination must be a canonical same-network P2MR address");
            }
            amountSats = parseSats(amount.getText(), "amount");
            maximumFeeSats = parseSats(maximumFee.getText(), "maximum fee");
            feeRateSats = Long.parseLong(feeRate.getText().trim());
            if(feeRateSats <= 0 || feeRateSats > 10_000) {
                throw new IllegalArgumentException("fee rate must be between 1 and 10000 sat/vB");
            }
        } catch(Exception e) {
            showError("Invalid spend", e);
            return;
        }
        long inputTotal;
        try {
            inputTotal = selected.stream().mapToLong(BtqCustodyWallet.Utxo::amountSats)
                    .reduce(0L, Math::addExact);
        } catch(ArithmeticException e) {
            showError("Invalid selected value", e);
            return;
        }
        long approvedInputTotal = inputTotal;
        runOperation("Building and locally validating an unsigned explicit-input P2MR PSBT…", () -> {
            BtqCustodyWallet.PreparedSpend prepared = current.prepareSpend(selected,
                    List.of(new BtqCustodyWallet.Payment(address, amountSats)),
                    feeRateSats, maximumFeeSats);
            BtqPsbtSigner.Review localReview = current.review(prepared);
            return new ReviewedSpend(prepared, localReview.feeSats());
        }, reviewed -> authorizeAndBroadcast(current, reviewed, address, amountSats, approvedInputTotal));
    }

    private void authorizeAndBroadcast(BtqCustodyWallet current, ReviewedSpend reviewed,
                                       String address, long amountSats, long inputTotal) {
        BtqCustodyWallet.PreparedSpend prepared = reviewed.prepared();
        long fee = reviewed.locallyValidatedFeeSats();
        long change = inputTotal - amountSats - fee;
        Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION);
        confirmation.setTitle("Authorize local ML-DSA signing");
        confirmation.setHeaderText("Sign and broadcast this P2MR transaction?");
        confirmation.setContentText("Inputs: " + prepared.selectedInputs().size() + " (" + formatSats(inputTotal)
                + " BTQ)\nDestination: " + address + "\nAmount: " + formatSats(amountSats)
                + " BTQ\nFee: " + formatSats(fee) + " BTQ\nChange: " + formatSats(change)
                + " BTQ\n\nQparrow will reparse the entire PSBT and sign locally only after this approval.");
        Optional<ButtonType> response = confirmation.showAndWait();
        if(response.isEmpty() || response.get() != ButtonType.OK) {
            status.setText("Spend cancelled before local signing");
            return;
        }
        resetSessionTimer();
        runOperation("Signing locally, finalizing, and broadcasting…", () -> {
            BtqPsbtSigner.SignedPsbt signed = current.sign(prepared);
            if(signed.feeSats() != reviewed.locallyValidatedFeeSats()) {
                throw new IllegalStateException("PSBT changed after local authorization review");
            }
            BtqWatchOnlyCore.FinalizedTransaction finalized = current.finalize(signed);
            return current.broadcast(finalized);
        }, broadcast -> {
            destination.clear();
            amount.clear();
            status.setText("Broadcast " + broadcast.txid());
            showInformation("P2MR transaction broadcast", broadcast.txid());
            refreshWallet();
        });
    }

    private void copyReceiveAddress() {
        String address = latestAddress.getText();
        if(connectedNetwork == null || !BtqP2mrAddressCodec.isCanonicalAddress(connectedNetwork, address)) return;
        ClipboardContent content = new ClipboardContent();
        content.putString(address);
        Clipboard.getSystemClipboard().setContent(content);
        resetSessionTimer();
        status.setText("Receive address copied");
    }

    private void lockSession(String message) {
        sessionTimer.stop();
        BtqCustodyWallet current = wallet;
        wallet = null;
        connectedNetwork = null;
        if(current != null) current.close();
        vaultPassword.clear();
        vaultConfirmation.clear();
        rpcPassword.clear();
        utxos.getItems().clear();
        balance.setText("0 BTQ");
        balanceDetail.setText("0 confirmed · 0 pending · 0 UTXOs");
        nodeStatus.setText("-");
        setConnectionControlsDisabled(false);
        setWalletControlsDisabled(true);
        lock.setDisable(true);
        backupWallet.setDisable(true);
        restoreWallet.setDisable(false);
        recoverWatch.setDisable(true);
        status.setText(message);
    }

    private void resetSessionTimer() {
        if(wallet != null) sessionTimer.playFromStart();
    }

    private BtqNodeProfile profileFromFields() {
        BtqAuthMode mode = authMode.getValue();
        Path cookie = mode == BtqAuthMode.COOKIE ? Path.of(cookieFile.getText().trim()) : null;
        return new BtqNodeProfile(URI.create(rpcUri.getText().trim()), walletName.getText().trim(),
                network.getValue(), mode, rpcUsername.getText().trim(), cookie, RPC_TIMEOUT);
    }

    private <T> void runOperation(String progress, ThrowingSupplier<T> operation, Consumer<T> success) {
        if(operationRunning) {
            showError("Operation in progress", new IllegalStateException("wait for the current custody operation to finish"));
            return;
        }
        operationRunning = true;
        sessionTimer.stop();
        status.setText(progress);
        setWalletControlsDisabled(true);
        setConnectionControlsDisabled(wallet != null);
        lock.setDisable(true);
        CompletableFuture.supplyAsync(() -> {
            try {
                return operation.get();
            } catch(Exception e) {
                throw new CompletionException(e);
            }
        }, worker).whenComplete((result, error) -> Platform.runLater(() -> {
            operationRunning = false;
            setConnectionControlsDisabled(wallet != null);
            setWalletControlsDisabled(wallet == null);
            lock.setDisable(wallet == null);
            if(wallet != null) resetSessionTimer();
            if(error != null) {
                status.setText("Operation failed: " + safeMessage(error));
                showError("BTQ custody operation failed", error);
            } else {
                if(wallet != null) status.setText("Unlocked on " + connectedNetwork);
                success.accept(result);
            }
        }));
    }

    private BtqCustodyWallet requireWallet() {
        BtqCustodyWallet current = wallet;
        if(current == null) showError("Wallet locked", new IllegalStateException("unlock the custody vault first"));
        return current;
    }

    private void setConnectionControlsDisabled(boolean disabled) {
        network.setDisable(disabled);
        rpcUri.setDisable(disabled);
        walletName.setDisable(disabled);
        authMode.setDisable(disabled);
        createWallet.setDisable(disabled || operationRunning);
        unlock.setDisable(disabled || operationRunning);
        backupWallet.setDisable(wallet == null || operationRunning);
        restoreWallet.setDisable(disabled || operationRunning);
        recoverWatch.setDisable(wallet == null || operationRunning);
        updateAuthFields();
    }

    private void setWalletControlsDisabled(boolean disabled) {
        refresh.setDisable(disabled);
        utxos.setDisable(disabled);
        receiveLabel.setDisable(disabled);
        newAddress.setDisable(disabled);
        copyAddress.setDisable(disabled);
        destination.setDisable(disabled);
        amount.setDisable(disabled);
        feeRate.setDisable(disabled);
        maximumFee.setDisable(disabled);
        reviewSpend.setDisable(disabled);
    }

    private void updateAuthFields() {
        boolean connectionLocked = wallet != null || network.isDisabled();
        BtqAuthMode mode = authMode.getValue();
        cookieFile.setDisable(connectionLocked || mode != BtqAuthMode.COOKIE);
        rpcUsername.setDisable(connectionLocked || mode != BtqAuthMode.BASIC);
        rpcPassword.setDisable(connectionLocked || mode != BtqAuthMode.BASIC);
    }

    private void updatePaths() {
        BtqNetwork selected = network.getValue();
        if(selected != null) vaultPath.setText(QparrowPaths.vault(selected).toString());
    }

    private static long parseSats(String value, String field) {
        try {
            long sats = new BigDecimal(value.trim()).movePointRight(8).longValueExact();
            if(sats <= 0 || sats > 21_000_000L * 100_000_000L) {
                throw new IllegalArgumentException(field + " is outside the monetary range");
            }
            return sats;
        } catch(NumberFormatException | ArithmeticException e) {
            throw new IllegalArgumentException(field + " must be a positive BTQ amount with at most 8 decimals", e);
        }
    }

    private static String formatSats(long sats) {
        return BigDecimal.valueOf(sats, 8).stripTrailingZeros().toPlainString();
    }

    private static String abbreviate(String value) {
        return value.length() <= 25 ? value : value.substring(0, 12) + "…" + value.substring(value.length() - 10);
    }

    private static String defaultRpcUri(BtqNetwork value) {
        return "http://127.0.0.1:" + value.rpcPort() + "/";
    }

    private static Path defaultCookieFile(BtqNetwork value) {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        Path data;
        if(os.contains("mac")) {
            data = Path.of(System.getProperty("user.home"), "Library", "Application Support", "BTQ");
        } else if(os.contains("win")) {
            String appData = System.getenv("APPDATA");
            data = Path.of(appData == null ? System.getProperty("user.home") : appData, "BTQ");
        } else {
            data = Path.of(System.getProperty("user.home"), ".btq");
        }
        String subdirectory = switch(value) {
            case MAINNET -> "";
            case TESTNET -> "test";
            case SIGNET -> "signet";
            case REGTEST -> "regtest";
        };
        return subdirectory.isEmpty() ? data.resolve(".cookie") : data.resolve(subdirectory).resolve(".cookie");
    }

    private static void addRow(GridPane grid, int row, String text, Control field) {
        grid.add(mutedLabel(text), 0, row);
        grid.add(field, 1, row);
        GridPane.setHgrow(field, Priority.ALWAYS);
        field.setMaxWidth(Double.MAX_VALUE);
    }

    private static Label heading(String text) {
        Label label = new Label(text);
        label.setStyle(HEADING_STYLE);
        return label;
    }

    private static Label section(String text) {
        Label label = new Label(text);
        label.setStyle("-fx-font-size: 15px; -fx-font-weight: bold; -fx-text-fill: #64e6c4;");
        return label;
    }

    private static Label mutedLabel(String text) {
        Label label = new Label(text);
        label.setStyle(MUTED_STYLE);
        return label;
    }

    private static Label valueLabel(String text) {
        Label label = new Label(text);
        label.setStyle(VALUE_STYLE);
        return label;
    }

    private static String safeMessage(Throwable throwable) {
        Throwable current = throwable;
        while(current.getCause() != null) current = current.getCause();
        return current.getMessage() == null || current.getMessage().isBlank()
                ? current.getClass().getSimpleName() : current.getMessage();
    }

    private static void showError(String title, Throwable error) {
        LOG.warn(title + ": " + safeMessage(error));
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.setContentText(safeMessage(error));
        alert.showAndWait();
    }

    private static void showInformation(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.setContentText(message);
        alert.showAndWait();
    }

    @Override
    public void stop() throws Exception {
        lockSession("Wallet locked");
        worker.shutdownNow();
        QparrowLauncher.freeInstanceLock();
        super.stop();
    }

    @FunctionalInterface
    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    private record ReviewedSpend(BtqCustodyWallet.PreparedSpend prepared, long locallyValidatedFeeSats) {
    }
}
