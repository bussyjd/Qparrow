package com.sparrowwallet.sparrow.net.btq;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** HTTP transport for BTQ Core JSON-RPC. */
public final class BtqHttpRpcTransport implements BtqRpcTransport {
    private final HttpClient httpClient;

    public BtqHttpRpcTransport() {
        this(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
    }

    BtqHttpRpcTransport(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public JsonObject send(URI endpoint, String authorizationHeader, Duration timeout, JsonObject request) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(request.toString()));
        if(authorizationHeader != null) {
            builder.header("Authorization", authorizationHeader);
        }

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if(response.statusCode() == 401 || response.statusCode() == 403) {
            throw new IOException("BTQ Core RPC authentication failed (HTTP " + response.statusCode() + ")");
        }
        if(response.body() == null || response.body().isBlank()) {
            throw new IOException("BTQ Core RPC returned an empty response (HTTP " + response.statusCode() + ")");
        }

        try {
            return JsonParser.parseString(response.body()).getAsJsonObject();
        } catch(RuntimeException e) {
            throw new IOException("BTQ Core RPC returned invalid JSON (HTTP " + response.statusCode() + ")", e);
        }
    }
}
