// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.net.btq;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.URI;
import java.util.concurrent.atomic.AtomicLong;

/** Small, typed-at-the-boundary JSON-RPC client that never handles wallet private keys. */
public final class BtqRpcClient {
    private static final Gson GSON = new Gson();

    private final BtqNodeConfig config;
    private final BtqRpcTransport transport;
    private final boolean walletScoped;
    private final AtomicLong requestIds;

    public BtqRpcClient(BtqNodeConfig config) {
        this(config, new BtqHttpRpcTransport(), false, new AtomicLong());
    }

    public BtqRpcClient(BtqNodeConfig config, BtqRpcTransport transport) {
        this(config, transport, false, new AtomicLong());
    }

    private BtqRpcClient(BtqNodeConfig config, BtqRpcTransport transport, boolean walletScoped, AtomicLong requestIds) {
        this.config = config;
        this.transport = transport;
        this.walletScoped = walletScoped;
        this.requestIds = requestIds;
    }

    public BtqRpcClient wallet() {
        return walletScoped ? this : new BtqRpcClient(config, transport, true, requestIds);
    }

    public BtqRpcClient node() {
        return walletScoped ? new BtqRpcClient(config, transport, false, requestIds) : this;
    }

    public JsonElement call(String method, Object... params) {
        JsonObject request = new JsonObject();
        request.addProperty("jsonrpc", "2.0");
        request.addProperty("id", requestIds.incrementAndGet());
        request.addProperty("method", method);
        JsonArray paramArray = new JsonArray();
        for(Object param : params) {
            paramArray.add(param == null ? JsonNull.INSTANCE : GSON.toJsonTree(param));
        }
        request.add("params", paramArray);

        URI endpoint = walletScoped ? config.walletEndpoint() : config.nodeEndpoint();
        JsonObject response;
        try {
            response = transport.send(endpoint, config.credentials().authorizationHeader(), config.requestTimeout(), request);
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new BtqRpcException(method, "request interrupted", e);
        } catch(IOException e) {
            throw new BtqRpcException(method, e.getMessage(), e);
        }

        JsonElement errorElement = response.get("error");
        if(errorElement != null && !errorElement.isJsonNull()) {
            JsonObject error = errorElement.getAsJsonObject();
            int code = error.has("code") ? error.get("code").getAsInt() : Integer.MIN_VALUE;
            String message = error.has("message") ? error.get("message").getAsString() : "Unknown RPC error";
            throw new BtqRpcException(method, code, message);
        }
        if(!response.has("id") || !response.get("id").isJsonPrimitive()
                || response.get("id").getAsLong() != request.get("id").getAsLong()) {
            throw new BtqRpcException(method, "response id did not match the request", null);
        }
        if(!response.has("result")) {
            throw new BtqRpcException(method, "response did not contain a result", null);
        }
        return response.get("result");
    }

    public JsonObject callObject(String method, Object... params) {
        JsonElement result = call(method, params);
        if(result == null || !result.isJsonObject()) {
            throw new BtqRpcException(method, "expected an object result", null);
        }
        return result.getAsJsonObject();
    }

    public JsonArray callArray(String method, Object... params) {
        JsonElement result = call(method, params);
        if(result == null || !result.isJsonArray()) {
            throw new BtqRpcException(method, "expected an array result", null);
        }
        return result.getAsJsonArray();
    }

    public String callString(String method, Object... params) {
        JsonElement result = call(method, params);
        if(result == null || result.isJsonNull() || !result.isJsonPrimitive() || !result.getAsJsonPrimitive().isString()) {
            throw new BtqRpcException(method, "expected a string result", null);
        }
        return result.getAsString();
    }
}
