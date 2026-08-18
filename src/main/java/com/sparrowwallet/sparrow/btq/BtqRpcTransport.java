// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;

@FunctionalInterface
public interface BtqRpcTransport {
    JsonObject send(URI endpoint, String authorizationHeader, Duration timeout, JsonObject request) throws IOException, InterruptedException;
}
