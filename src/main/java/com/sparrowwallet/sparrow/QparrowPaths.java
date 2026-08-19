// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow;

import com.sparrowwallet.sparrow.btq.BtqNetwork;

import java.nio.file.Path;

/** Qparrow-owned paths, deliberately independent of Sparrow's application identity. */
public final class QparrowPaths {
    private QparrowPaths() {
    }

    public static Path configHome() {
        String configured = System.getProperty(QparrowLauncher.APP_HOME_PROPERTY);
        if(configured != null && !configured.isBlank()) {
            return Path.of(configured).toAbsolutePath().normalize();
        }
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if(os.contains("mac")) {
            return Path.of(System.getProperty("user.home"), "Library", "Application Support", "Qparrow")
                    .toAbsolutePath().normalize();
        }
        if(os.contains("win")) {
            String appData = System.getenv("APPDATA");
            return Path.of(appData == null || appData.isBlank() ? System.getProperty("user.home") : appData,
                    "Qparrow").toAbsolutePath().normalize();
        }
        String xdg = System.getenv("XDG_CONFIG_HOME");
        Path base = xdg != null && !xdg.isBlank() && Path.of(xdg).isAbsolute()
                ? Path.of(xdg) : Path.of(System.getProperty("user.home"), ".config");
        return base.resolve("qparrow").toAbsolutePath().normalize();
    }

    public static Path vault(BtqNetwork network) {
        return configHome().resolve(network.name().toLowerCase(java.util.Locale.ROOT) + ".qpbtq");
    }

    public static Path state(BtqNetwork network) {
        return configHome().resolve(network.name().toLowerCase(java.util.Locale.ROOT) + ".qpstate");
    }
}
