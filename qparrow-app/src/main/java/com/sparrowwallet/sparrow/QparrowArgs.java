// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow;

import com.beust.jcommander.Parameter;
import com.sparrowwallet.sparrow.btq.BtqNetwork;

final class QparrowArgs {
    @Parameter(names = {"--dir", "-d"}, description = "Path to Qparrow home folder")
    String directory;

    @Parameter(names = {"--network", "-n"}, description = "BTQ network")
    BtqNetwork network;

    @Parameter(names = {"--version", "-v"}, description = "Show version", arity = 0)
    boolean version;

    @Parameter(names = {"--help", "-h"}, description = "Show help", help = true, arity = 0)
    boolean help;
}
