// Modified for Qparrow: independent launcher and node-backed BTQ runtime.
package com.sparrowwallet.sparrow;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.sparrowwallet.drongo.ApplicationDir;
import com.sparrowwallet.drongo.Drongo;
import com.sparrowwallet.drongo.Network;
import com.sparrowwallet.sparrow.btq.BtqNetwork;
import com.sparrowwallet.sparrow.io.Storage;
import com.sparrowwallet.sparrow.instance.InstanceException;
import com.sparrowwallet.sparrow.instance.InstanceList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.bridge.SLF4JBridgeHandler;

import java.io.File;
import java.util.*;

public class SparrowWallet {
    public static final String APP_ID = "qparrow";
    public static final String APP_NAME = "Qparrow";
    public static final String APP_VERSION = "0.1.0";
    public static final String APP_VERSION_SUFFIX = "-dev";
    public static final String APP_HOME_PROPERTY = ApplicationDir.getHomeProperty(APP_NAME);
    public static final String NETWORK_ENV_PROPERTY = "QPARROW_NETWORK";
    public static final String JPACKAGE_APP_PATH = "jpackage.app-path";

    private static Instance instance;

    public static void main(String[] argv) {
        if(System.getProperty(JPACKAGE_APP_PATH) != null) {
            String libDir = System.getProperty("java.home") + File.separator + "lib";
            System.setProperty("jna.boot.library.path", libDir);
            System.setProperty("jna.library.path", libDir);
            System.setProperty("jSerialComm.library.path", libDir);
            System.setProperty("org.usb4java.LibraryName", "usb4java");
            System.setProperty("java.library.path", libDir);
        }

        Args args = new Args();
        JCommander jCommander = JCommander.newBuilder().addObject(args).programName(APP_NAME.toLowerCase(Locale.ROOT)).build();
        try {
            jCommander.parse(argv);
        } catch(ParameterException e) {
            System.err.println(e.getMessage());
            jCommander.usage();
            System.exit(2);
        }
        if(args.help) {
            jCommander.usage();
            System.exit(0);
        }

        if(args.version) {
            System.out.println(APP_NAME + " " + APP_VERSION + APP_VERSION_SUFFIX);
            System.exit(0);
        }

        if(args.level != null) {
            Drongo.setRootLogLevel(args.level);
        }

        if(args.dir != null) {
            System.setProperty(APP_HOME_PROPERTY, args.dir);
            getLogger().info("Using configured " + APP_NAME + " home folder of " + args.dir);
        }

        if(args.network != null) {
            Network.set(args.network);
            QparrowDesktop.setInitialNetwork(toBtqNetwork(args.network));
        } else {
            String envNetwork = System.getenv(NETWORK_ENV_PROPERTY);
            if(envNetwork != null) {
                try {
                    QparrowDesktop.setInitialNetwork(BtqNetwork.valueOf(envNetwork.toUpperCase(Locale.ROOT)));
                } catch(Exception e) {
                    getLogger().warn("Invalid " + NETWORK_ENV_PROPERTY + " property: " + envNetwork);
                }
            }
        }

        Storage.logApplicationDirs();

        try {
            instance = new Instance(List.of());
            instance.acquireLock(false);
        } catch(InstanceException e) {
            getLogger().error("Could not access application lock", e);
        }

        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();

        if(args.terminal) {
            System.err.println("Qparrow terminal and inherited Sparrow wallet modes are disabled in the node-backed BTQ milestone.");
            System.exit(2);
        }

        try {
            com.sun.javafx.application.LauncherImpl.launchApplication(QparrowDesktop.class, SparrowWalletPreloader.class, argv);
        } catch(UnsupportedOperationException e) {
            Drongo.removeRootLogAppender("STDOUT");
            getLogger().error("Unable to launch application", e);
            System.out.println("No display detected. Qparrow's node-backed desktop requires a graphical session.");

            try {
                if(instance != null) {
                    instance.freeLock();
                }
            } catch(InstanceException instanceException) {
                getLogger().error("Unable to free instance lock", e);
            }
        }
    }

    public static Instance getSparrowInstance() {
        return instance;
    }

    private static Logger getLogger() {
        return LoggerFactory.getLogger(SparrowWallet.class);
    }

    private static BtqNetwork toBtqNetwork(Network network) {
        return switch(network) {
            case MAINNET -> BtqNetwork.MAINNET;
            case TESTNET, TESTNET4 -> BtqNetwork.TESTNET;
            case SIGNET -> BtqNetwork.SIGNET;
            case REGTEST -> BtqNetwork.REGTEST;
        };
    }

    public static class Instance extends InstanceList {
        private final List<String> fileUriArguments;

        public Instance(List<String> fileUriArguments) {
            super(SparrowWallet.APP_ID, true);
            this.fileUriArguments = fileUriArguments;
        }

        @Override
        protected void receiveMessageList(List<String> messageList) {
            getLogger().warn("Ignoring external open request: Qparrow does not open Sparrow wallet files or URIs");
        }

        @Override
        protected List<String> sendMessageList() {
            return fileUriArguments;
        }

        @Override
        protected void beforeExit() {
            getLogger().info("Another Qparrow instance is already running; exiting...");
        }
    }
}
