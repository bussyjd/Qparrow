// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow;

import com.sparrowwallet.sparrow.btq.BtqAuthMode;
import com.sparrowwallet.sparrow.btq.BtqCoreWallet;
import com.sparrowwallet.sparrow.btq.BtqNetwork;
import com.sparrowwallet.sparrow.btq.BtqNodeProfile;
import com.sparrowwallet.sparrow.btq.BtqNodeProfileStore;
import com.sparrowwallet.sparrow.btq.BtqP2mrAddressCodec;
import com.sparrowwallet.sparrow.io.Storage;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Separator;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Qparrow's deliberately small BTQ-only desktop surface. It does not open
 * Sparrow wallet files, instantiate Drongo wallets, derive keys, parse BTQ
 * transactions, or call hardware signing paths. All signing remains in BTQ Core.
 */
public final class QparrowDesktop extends Application {
    private static final Logger LOG = LoggerFactory.getLogger(QparrowDesktop.class);
    private static final String WINDOW_STYLE = "-fx-font-family: system; -fx-font-size: 13px; -fx-background-color: #11151b;";
    private static final String CARD_STYLE = "-fx-background-color: #1b222c; -fx-background-radius: 10; -fx-padding: 18;";
    private static final String HEADING_STYLE = "-fx-font-size: 20px; -fx-font-weight: bold; -fx-text-fill: #f4f7fb;";
    private static final String MUTED_STYLE = "-fx-text-fill: #9aa7b6;";
    private static final String VALUE_STYLE = "-fx-text-fill: #f4f7fb; -fx-font-family: monospace;";

    private final ExecutorService rpcExecutor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "qparrow-btq-rpc");
        thread.setDaemon(true);
        return thread;
    });

    private final ComboBox<BtqNetwork> network = new ComboBox<>();
    private final TextField rpcUri = new TextField();
    private final TextField walletName = new TextField("qparrow");
    private final ComboBox<BtqAuthMode> authMode = new ComboBox<>();
    private final TextField cookieFile = new TextField();
    private final TextField rpcUsername = new TextField();
    private final PasswordField rpcPassword = new PasswordField();
    private final Button connect = new Button("Connect to BTQ Core");
    private final Label connectionStatus = new Label("Not connected");

    private final Label nodeStatus = valueLabel("-");
    private final Label balance = valueLabel("0 BTQ");
    private final Label balanceDetail = mutedLabel("0 confirmed · 0 pending · 0 P2MR UTXOs");
    private final ListView<BtqCoreWallet.P2mrEntry> p2mrEntries = new ListView<>();
    private final TextField receiveLabel = new TextField();
    private final Label latestAddress = valueLabel("No P2MR receive address yet");
    private final Button newAddress = new Button("New quantum-safe address");
    private final TextField destination = new TextField();
    private final TextField amount = new TextField();
    private final TextField fee = new TextField("0.00001");
    private final Button send = new Button("Review P2MR spend");
    private final Button refresh = new Button("Refresh");

    private BtqNodeProfileStore profileStore;
    private volatile BtqCoreWallet wallet;
    private volatile BtqNetwork connectedNetwork;
    private static volatile BtqNetwork initialNetwork = BtqNetwork.REGTEST;

    public static void setInitialNetwork(BtqNetwork network) {
        initialNetwork = network;
    }

    @Override
    public void start(Stage stage) {
        profileStore = new BtqNodeProfileStore(Storage.getConfigHome().toPath());
        configureFields();
        loadProfile();

        BorderPane root = new BorderPane();
        root.setPadding(new Insets(20));
        root.setStyle(WINDOW_STYLE);
        root.setTop(header());
        root.setCenter(content());

        Scene scene = new Scene(root, 960, 760);
        stage.setTitle(SparrowWallet.APP_NAME + " — Bitcoin Quantum Wallet");
        stage.setMinWidth(820);
        stage.setMinHeight(680);
        stage.setScene(scene);
        stage.show();
    }

    private VBox header() {
        Label title = new Label("Qparrow");
        title.setStyle("-fx-font-size: 28px; -fx-font-weight: bold; -fx-text-fill: #64e6c4;");
        Label subtitle = mutedLabel("Node-backed Bitcoin Quantum wallet · ML-DSA keys and signing stay inside BTQ Core");
        VBox box = new VBox(4, title, subtitle, new Separator());
        box.setPadding(new Insets(0, 0, 16, 0));
        return box;
    }

    private HBox content() {
        VBox connection = connectionCard();
        VBox walletCard = walletCard();
        HBox.setHgrow(connection, Priority.ALWAYS);
        HBox.setHgrow(walletCard, Priority.ALWAYS);
        connection.setMaxWidth(Double.MAX_VALUE);
        walletCard.setMaxWidth(Double.MAX_VALUE);
        return new HBox(16, connection, walletCard);
    }

    private VBox connectionCard() {
        Label heading = new Label("BTQ Core connection");
        heading.setStyle(HEADING_STYLE);
        Label warning = mutedLabel("Only public connection metadata is stored. RPC passwords are memory-only.");
        warning.setWrapText(true);

        GridPane grid = new GridPane();
        grid.setHgap(10);
        grid.setVgap(10);
        addRow(grid, 0, "Network", network);
        addRow(grid, 1, "RPC URI", rpcUri);
        addRow(grid, 2, "Wallet", walletName);
        addRow(grid, 3, "Authentication", authMode);
        addRow(grid, 4, "Cookie file", cookieFile);
        addRow(grid, 5, "RPC username", rpcUsername);
        addRow(grid, 6, "RPC password", rpcPassword);

        connectionStatus.setWrapText(true);
        connectionStatus.setStyle(MUTED_STYLE);
        connect.setMaxWidth(Double.MAX_VALUE);
        connect.setOnAction(event -> connect());

        VBox card = new VBox(12, heading, warning, grid, connect, connectionStatus);
        card.setStyle(CARD_STYLE);
        card.setPrefWidth(420);
        return card;
    }

    private VBox walletCard() {
        Label heading = new Label("Quantum-safe wallet");
        heading.setStyle(HEADING_STYLE);
        Label custody = mutedLabel("BTQ Core owns the seed, Dilithium keys, P2MR metadata, signing, and finalization.");
        custody.setWrapText(true);

        nodeStatus.setWrapText(true);
        balance.setStyle("-fx-font-size: 24px; -fx-font-weight: bold; -fx-text-fill: #f4f7fb;");
        refresh.setOnAction(event -> refreshWallet());

        HBox balanceLine = new HBox(10, balance, refresh);
        balanceLine.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(balance, Priority.ALWAYS);

        Label receiveHeading = sectionLabel("Receive to P2MR / ML-DSA");
        receiveLabel.setPromptText("Optional label");
        newAddress.setOnAction(event -> newAddress());
        latestAddress.setWrapText(true);
        Button copy = new Button("Copy");
        copy.setOnAction(event -> copyAddress());
        HBox receiveActions = new HBox(8, receiveLabel, newAddress);
        HBox.setHgrow(receiveLabel, Priority.ALWAYS);
        HBox addressLine = new HBox(8, latestAddress, copy);
        HBox.setHgrow(latestAddress, Priority.ALWAYS);

        p2mrEntries.setPrefHeight(115);
        p2mrEntries.setPlaceholder(new Label("Connect to list node-owned P2MR entries"));
        p2mrEntries.setCellFactory(list -> new ListCell<>() {
            @Override
            protected void updateItem(BtqCoreWallet.P2mrEntry item, boolean empty) {
                super.updateItem(item, empty);
                setText(empty || item == null ? null : (item.label().isBlank() ? "P2MR" : item.label()) + " · " + item.address());
            }
        });

        Label sendHeading = sectionLabel("Send — P2MR destinations only");
        destination.setPromptText("BTQ P2MR address");
        amount.setPromptText("Amount BTQ");
        send.setMaxWidth(Double.MAX_VALUE);
        send.setOnAction(event -> reviewSpend());
        GridPane sendGrid = new GridPane();
        sendGrid.setHgap(8);
        sendGrid.setVgap(8);
        addRow(sendGrid, 0, "Destination", destination);
        addRow(sendGrid, 1, "Amount", amount);
        addRow(sendGrid, 2, "Fixed fee", fee);

        VBox card = new VBox(10, heading, custody, nodeStatus, balanceLine, balanceDetail,
                new Separator(), receiveHeading, receiveActions, addressLine, p2mrEntries,
                new Separator(), sendHeading, sendGrid, send);
        card.setStyle(CARD_STYLE);
        card.setPrefWidth(490);
        setWalletControlsDisabled(true);
        return card;
    }

    private void configureFields() {
        network.getItems().setAll(BtqNetwork.values());
        network.setValue(initialNetwork);
        authMode.getItems().setAll(BtqAuthMode.values());
        authMode.setValue(BtqAuthMode.COOKIE);
        rpcUri.setText(defaultRpcUri(initialNetwork));
        cookieFile.setText(defaultCookieFile(initialNetwork).toString());

        rpcUri.setTooltip(new Tooltip("HTTP is allowed only for loopback. Remote BTQ nodes require HTTPS."));
        walletName.setTooltip(new Tooltip("BTQ Core wallet name; Qparrow does not create a local key store."));
        p2mrEntries.setTooltip(new Tooltip("Select the node-owned P2MR metadata entry whose UTXO will be spent."));

        authMode.valueProperty().addListener((observable, oldValue, newValue) -> updateAuthFields());
        network.valueProperty().addListener((observable, oldValue, newValue) -> {
            if(newValue != null && (oldValue == null || rpcUri.getText().equals(defaultRpcUri(oldValue)))) {
                rpcUri.setText(defaultRpcUri(newValue));
            }
            if(newValue != null && (oldValue == null || cookieFile.getText().equals(defaultCookieFile(oldValue).toString()))) {
                cookieFile.setText(defaultCookieFile(newValue).toString());
            }
        });
        updateAuthFields();
    }

    private void loadProfile() {
        try {
            Optional<BtqNodeProfile> loaded = profileStore.load();
            if(loaded.isPresent()) {
                BtqNodeProfile profile = loaded.get();
                network.setValue(profile.network());
                rpcUri.setText(profile.rpcUri().toString());
                walletName.setText(profile.walletName());
                authMode.setValue(profile.authMode());
                rpcUsername.setText(profile.rpcUsername());
                if(profile.cookieFile() != null) {
                    cookieFile.setText(profile.cookieFile().toString());
                }
            }
        } catch(Exception e) {
            connectionStatus.setText("Profile was not loaded: " + safeMessage(e));
        }
    }

    private void connect() {
        char[] password = rpcPassword.getText().toCharArray();
        final BtqNodeProfile profile;
        try {
            profile = profileFromFields();
        } catch(Exception e) {
            Arrays.fill(password, '\0');
            showError("Invalid BTQ node settings", e);
            return;
        }

        connect.setDisable(true);
        setWalletControlsDisabled(true);
        connectionStatus.setText("Verifying BTQ Core identity and network…");
        CompletableFuture.supplyAsync(() -> {
            BtqCoreWallet candidate = new BtqCoreWallet(profile.toConfig(password));
            Arrays.fill(password, '\0');
            BtqCoreWallet.NodeStatus status = candidate.verifyNode();
            BtqCoreWallet.WalletStatus walletStatus = candidate.ensureWallet();
            try {
                profileStore.save(profile);
            } catch(Exception e) {
                throw new IllegalStateException("Connected, but the public BTQ node profile could not be saved", e);
            }
            return new Connected(candidate, status, walletStatus);
        }, rpcExecutor).whenComplete((connected, error) -> Platform.runLater(() -> {
            connect.setDisable(false);
            if(error != null) {
                Arrays.fill(password, '\0');
                wallet = null;
                connectedNetwork = null;
                setWalletControlsDisabled(true);
                connectionStatus.setText("Connection failed: " + safeMessage(error));
                return;
            }
            wallet = connected.wallet();
            connectedNetwork = connected.status().network();
            setWalletControlsDisabled(false);
            connectionStatus.setText("Connected to " + connected.status().subversion() + " on " + connected.status().network());
            nodeStatus.setText(connected.status().blocks() + " blocks / " + connected.status().headers() + " headers · wallet " + connected.walletStatus().name());
            refreshWallet();
        }));
    }

    private void refreshWallet() {
        BtqCoreWallet current = requireWallet();
        if(current == null) return;
        runRpc("Refreshing P2MR state…", () -> new WalletSnapshot(current.getQuantumBalance(), current.listQuantumAddresses()), snapshot -> {
            balance.setText(format(snapshot.balance().total()) + " BTQ");
            balanceDetail.setText(format(snapshot.balance().confirmed()) + " confirmed · " + format(snapshot.balance().pending())
                    + " pending · " + snapshot.balance().utxoCount() + " P2MR UTXOs");
            BtqCoreWallet.P2mrEntry selected = p2mrEntries.getSelectionModel().getSelectedItem();
            p2mrEntries.getItems().setAll(snapshot.entries());
            if(selected != null) {
                snapshot.entries().stream().filter(entry -> entry.id().equals(selected.id())).findFirst()
                        .ifPresent(entry -> p2mrEntries.getSelectionModel().select(entry));
            }
            if(p2mrEntries.getSelectionModel().isEmpty() && !snapshot.entries().isEmpty()) {
                p2mrEntries.getSelectionModel().selectFirst();
            }
        });
    }

    private void newAddress() {
        BtqCoreWallet current = requireWallet();
        if(current == null) return;
        runRpc("Asking BTQ Core for a new Dilithium P2MR address…", () -> current.newQuantumAddress(receiveLabel.getText()), created -> {
            latestAddress.setText(created.address());
            receiveLabel.clear();
            refreshWallet();
        });
    }

    private void reviewSpend() {
        BtqCoreWallet current = requireWallet();
        if(current == null) return;
        BtqCoreWallet.P2mrEntry source = p2mrEntries.getSelectionModel().getSelectedItem();
        if(source == null) {
            showError("No P2MR source selected", new IllegalArgumentException("Create and fund a P2MR receive address first"));
            return;
        }

        final BigDecimal spendAmount;
        final BigDecimal spendFee;
        try {
            spendAmount = new BigDecimal(amount.getText().trim());
            spendFee = new BigDecimal(fee.getText().trim());
        } catch(NumberFormatException e) {
            showError("Invalid amount", new IllegalArgumentException("Amount and fee must be decimal BTQ values"));
            return;
        }
        String spendDestination = destination.getText().trim();
        runRpc("Building unsigned P2MR transaction in BTQ Core…",
                () -> current.createSpend(source.id(), spendDestination, spendAmount, spendFee),
                draft -> confirmAndBroadcast(current, source, spendDestination, spendAmount, draft));
    }

    private void confirmAndBroadcast(BtqCoreWallet current, BtqCoreWallet.P2mrEntry source, String spendDestination,
                                     BigDecimal spendAmount, BtqCoreWallet.SpendDraft draft) {
        Alert confirmation = new Alert(Alert.AlertType.CONFIRMATION);
        confirmation.setTitle("Authorize BTQ Core signing");
        confirmation.setHeaderText("Sign and broadcast this quantum-safe P2MR spend?");
        confirmation.setContentText("Source: " + source.address() + "\nDestination: " + spendDestination
                + "\nAmount: " + format(spendAmount) + " BTQ\nFee: " + format(draft.effectiveFee())
                + " BTQ\nChange: " + format(draft.changeAmount()) + " BTQ\nUnsigned txid: " + draft.txid()
                + "\n\nBTQ Core—not Qparrow—will use the ML-DSA key after confirmation.");
        Optional<ButtonType> response = confirmation.showAndWait();
        if(response.isEmpty() || response.get() != ButtonType.OK) {
            connectionStatus.setText("Spend cancelled before signing");
            return;
        }

        runRpc("BTQ Core is signing, dry-running mempool acceptance, and broadcasting…", () -> {
            BtqCoreWallet.SignedTransaction signed = current.signSpend(draft);
            return current.broadcast(signed);
        }, broadcast -> {
            destination.clear();
            amount.clear();
            connectionStatus.setText("Broadcast P2MR transaction " + broadcast.txid());
            showInformation("P2MR transaction broadcast", "BTQ Core accepted and broadcast:\n" + broadcast.txid());
            refreshWallet();
        });
    }

    private BtqNodeProfile profileFromFields() {
        BtqAuthMode mode = authMode.getValue();
        Path cookie = mode == BtqAuthMode.COOKIE ? Path.of(cookieFile.getText().trim()) : null;
        return new BtqNodeProfile(
                URI.create(rpcUri.getText().trim()),
                walletName.getText().trim(),
                network.getValue(),
                mode,
                rpcUsername.getText().trim(),
                cookie,
                Duration.ofSeconds(30)
        );
    }

    private <T> void runRpc(String progress, Supplier<T> operation, Consumer<T> success) {
        connectionStatus.setText(progress);
        setWalletControlsDisabled(true);
        CompletableFuture.supplyAsync(operation, rpcExecutor).whenComplete((result, error) -> Platform.runLater(() -> {
            setWalletControlsDisabled(wallet == null);
            if(error != null) {
                connectionStatus.setText("BTQ operation failed: " + safeMessage(error));
                showError("BTQ Core operation failed", error);
            } else {
                connectionStatus.setText("Connected to BTQ Core on " + connectedNetwork);
                success.accept(result);
            }
        }));
    }

    private void setWalletControlsDisabled(boolean disabled) {
        refresh.setDisable(disabled);
        newAddress.setDisable(disabled);
        receiveLabel.setDisable(disabled);
        p2mrEntries.setDisable(disabled);
        destination.setDisable(disabled);
        amount.setDisable(disabled);
        fee.setDisable(disabled);
        send.setDisable(disabled);
    }

    private BtqCoreWallet requireWallet() {
        BtqCoreWallet current = wallet;
        if(current == null) {
            showError("Not connected", new IllegalStateException("Connect to a verified BTQ Core node first"));
        }
        return current;
    }

    private void copyAddress() {
        String address = latestAddress.getText();
        if(address == null || connectedNetwork == null || !BtqP2mrAddressCodec.isCanonicalAddress(connectedNetwork, address)) {
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(address);
        Clipboard.getSystemClipboard().setContent(content);
        connectionStatus.setText("Copied P2MR address");
    }

    private void updateAuthFields() {
        BtqAuthMode mode = authMode.getValue();
        cookieFile.setDisable(mode != BtqAuthMode.COOKIE);
        rpcUsername.setDisable(mode != BtqAuthMode.BASIC);
        rpcPassword.setDisable(mode != BtqAuthMode.BASIC);
    }

    private static void addRow(GridPane grid, int row, String labelText, javafx.scene.control.Control field) {
        Label label = mutedLabel(labelText);
        grid.add(label, 0, row);
        grid.add(field, 1, row);
        GridPane.setHgrow(field, Priority.ALWAYS);
        field.setMaxWidth(Double.MAX_VALUE);
    }

    private static Label sectionLabel(String text) {
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

    private static String format(BigDecimal amount) {
        return amount.stripTrailingZeros().toPlainString();
    }

    private static String defaultRpcUri(BtqNetwork network) {
        return "http://127.0.0.1:" + network.rpcPort() + "/";
    }

    private static Path defaultCookieFile(BtqNetwork network) {
        String os = System.getProperty("os.name", "").toLowerCase();
        Path dataDirectory;
        if(os.contains("mac")) {
            dataDirectory = Path.of(System.getProperty("user.home"), "Library", "Application Support", "BTQ");
        } else if(os.contains("win")) {
            String appData = System.getenv("APPDATA");
            dataDirectory = Path.of(appData == null ? System.getProperty("user.home") : appData, "BTQ");
        } else {
            dataDirectory = Path.of(System.getProperty("user.home"), ".btq");
        }
        String networkDirectory = switch(network) {
            case MAINNET -> "";
            case TESTNET -> "test";
            case SIGNET -> "signet";
            case REGTEST -> "regtest";
        };
        return networkDirectory.isEmpty() ? dataDirectory.resolve(".cookie") : dataDirectory.resolve(networkDirectory).resolve(".cookie");
    }

    private static String safeMessage(Throwable error) {
        Throwable current = error;
        while(current.getCause() != null && (current.getMessage() == null || current.getMessage().isBlank())) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return message == null || message.isBlank() ? current.getClass().getSimpleName() : message;
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
        rpcExecutor.shutdownNow();
        SparrowWallet.Instance instance = SparrowWallet.getSparrowInstance();
        if(instance != null) {
            instance.freeLock();
        }
        super.stop();
    }

    private record Connected(BtqCoreWallet wallet, BtqCoreWallet.NodeStatus status, BtqCoreWallet.WalletStatus walletStatus) {}
    private record WalletSnapshot(BtqCoreWallet.QuantumBalance balance, List<BtqCoreWallet.P2mrEntry> entries) {}
}
