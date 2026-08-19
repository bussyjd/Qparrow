// Modified for Qparrow: node-backed Bitcoin Quantum wallet support.
package com.sparrowwallet.sparrow.btq;

public class BtqRpcException extends RuntimeException {
    private final String method;
    private final int code;

    public BtqRpcException(String method, int code, String message) {
        super("BTQ RPC " + method + " failed (" + code + "): " + message);
        this.method = method;
        this.code = code;
    }

    public BtqRpcException(String method, String message, Throwable cause) {
        super("BTQ RPC " + method + " failed: " + message, cause);
        this.method = method;
        this.code = Integer.MIN_VALUE;
    }

    public String getMethod() {
        return method;
    }

    public int getCode() {
        return code;
    }
}
