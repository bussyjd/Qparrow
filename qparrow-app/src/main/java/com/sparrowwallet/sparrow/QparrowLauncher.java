// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.sparrowwallet.sparrow.btq.BtqNetwork;
import javafx.application.Application;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.io.IOException;
import java.util.Locale;

/** Small Qparrow launcher kept separate from Sparrow's upstream launcher. */
public final class QparrowLauncher {
    public static final String APP_ID = "qparrow";
    public static final String APP_NAME = "Qparrow";
    public static final String APP_VERSION = "0.1.0";
    public static final String APP_VERSION_SUFFIX = "-dev";
    public static final String APP_HOME_PROPERTY = "qparrow.home";
    public static final String NETWORK_ENV_PROPERTY = "QPARROW_NETWORK";

    private static FileChannel lockChannel;
    private static FileLock instanceLock;

    private QparrowLauncher() {
    }

    public static void main(String[] argv) {
        Thread.setDefaultUncaughtExceptionHandler((thread, error) ->
                logger().error("Uncaught exception in " + thread.getName(), error));
        QparrowArgs args = new QparrowArgs();
        JCommander commander = JCommander.newBuilder().addObject(args).programName(APP_ID).build();
        try {
            commander.parse(argv);
        } catch(ParameterException e) {
            System.err.println(e.getMessage());
            commander.usage();
            System.exit(2);
        }
        if(args.help) {
            commander.usage();
            return;
        }
        if(args.version) {
            System.out.println(APP_NAME + " " + APP_VERSION + APP_VERSION_SUFFIX);
            return;
        }
        if(args.directory != null) {
            System.setProperty(APP_HOME_PROPERTY, args.directory);
        }

        BtqNetwork selected = args.network;
        if(selected == null) {
            String environment = System.getenv(NETWORK_ENV_PROPERTY);
            if(environment != null && !environment.isBlank()) {
                try {
                    selected = BtqNetwork.valueOf(environment.toUpperCase(Locale.ROOT));
                } catch(IllegalArgumentException e) {
                    logger().warn("Ignoring invalid " + NETWORK_ENV_PROPERTY + " value: " + environment);
                }
            }
        }
        QparrowDesktop.setInitialNetwork(selected == null ? BtqNetwork.REGTEST : selected);
        try {
            Files.createDirectories(QparrowPaths.configHome());
            acquireInstanceLock();
        } catch(Exception e) {
            logger().error("Could not initialize Qparrow's private application directory or lock", e);
            System.exit(2);
        }

        try {
            Application.launch(QparrowDesktop.class, argv);
        } catch(UnsupportedOperationException e) {
            logger().error("Unable to launch Qparrow desktop", e);
            freeInstanceLock();
        }
    }

    static void freeInstanceLock() {
        try {
            if(instanceLock != null && instanceLock.isValid()) instanceLock.release();
            if(lockChannel != null) lockChannel.close();
        } catch(IOException e) {
            logger().warn("Could not free Qparrow instance lock", e);
        } finally {
            instanceLock = null;
            lockChannel = null;
        }
    }

    private static void acquireInstanceLock() throws IOException {
        java.nio.file.Path path = QparrowPaths.configHome().resolve("qparrow.lock");
        if(Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Qparrow instance lock is not a regular file");
        }
        lockChannel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        try {
            instanceLock = lockChannel.tryLock();
        } catch(java.nio.channels.OverlappingFileLockException e) {
            instanceLock = null;
        }
        if(instanceLock == null) {
            lockChannel.close();
            lockChannel = null;
            throw new IOException("another Qparrow instance is already running");
        }
    }

    private static Logger logger() {
        return LoggerFactory.getLogger(QparrowLauncher.class);
    }

}
