// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Minimal Base58Check codec (Base58 with a 4-byte double-SHA256 checksum),
 * kept in-package so the custody module stays independent of Drongo.
 *
 * <p>Used only to encode/decode BTQ Dilithium secret-key WIFs so a Qparrow
 * derivation can be imported into BTQ Core via {@code importdilithiumkey};
 * it is not used anywhere in the signing path.</p>
 */
public final class BtqBase58Check {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final int[] INDEXES = new int[128];
    static {
        Arrays.fill(INDEXES, -1);
        for(int i = 0; i < ALPHABET.length(); i++) {
            INDEXES[ALPHABET.charAt(i)] = i;
        }
    }

    private BtqBase58Check() {
    }

    /** Encode {@code payload} as Base58Check (payload followed by its 4-byte checksum). */
    public static String encode(byte[] payload) {
        Objects.requireNonNull(payload, "payload");
        byte[] checksum = doubleSha256(payload);
        byte[] data = new byte[payload.length + 4];
        System.arraycopy(payload, 0, data, 0, payload.length);
        System.arraycopy(checksum, 0, data, payload.length, 4);
        try {
            return encodeBase58(data);
        } finally {
            Arrays.fill(data, (byte)0);
            Arrays.fill(checksum, (byte)0);
        }
    }

    /**
     * Decode a Base58Check string, verifying the checksum, and return the payload
     * without the trailing 4 checksum bytes.
     *
     * @throws IllegalArgumentException if the string is not valid Base58 or the checksum fails
     */
    public static byte[] decode(String encoded) {
        Objects.requireNonNull(encoded, "encoded");
        byte[] data = decodeBase58(encoded);
        if(data.length < 4) {
            throw new IllegalArgumentException("Base58Check input is too short");
        }
        byte[] payload = Arrays.copyOfRange(data, 0, data.length - 4);
        byte[] expected = doubleSha256(payload);
        boolean ok = true;
        for(int i = 0; i < 4; i++) {
            ok &= expected[i] == data[data.length - 4 + i];
        }
        Arrays.fill(expected, (byte)0);
        if(!ok) {
            Arrays.fill(payload, (byte)0);
            Arrays.fill(data, (byte)0);
            throw new IllegalArgumentException("Base58Check checksum mismatch");
        }
        Arrays.fill(data, (byte)0);
        return payload;
    }

    private static String encodeBase58(byte[] input) {
        if(input.length == 0) {
            return "";
        }
        byte[] copy = Arrays.copyOf(input, input.length);
        int zeros = 0;
        while(zeros < copy.length && copy[zeros] == 0) {
            zeros++;
        }
        char[] encoded = new char[copy.length * 2];
        int outputStart = encoded.length;
        for(int inputStart = zeros; inputStart < copy.length; ) {
            encoded[--outputStart] = ALPHABET.charAt(divmod(copy, inputStart, 256, 58));
            if(copy[inputStart] == 0) {
                inputStart++;
            }
        }
        while(outputStart < encoded.length && encoded[outputStart] == ALPHABET.charAt(0)) {
            outputStart++;
        }
        while(--zeros >= 0) {
            encoded[--outputStart] = ALPHABET.charAt(0);
        }
        Arrays.fill(copy, (byte)0);
        return new String(encoded, outputStart, encoded.length - outputStart);
    }

    private static byte[] decodeBase58(String input) {
        if(input.isEmpty()) {
            return new byte[0];
        }
        byte[] input58 = new byte[input.length()];
        for(int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if(digit < 0) {
                throw new IllegalArgumentException("Invalid Base58 character '" + c + "'");
            }
            input58[i] = (byte)digit;
        }
        int zeros = 0;
        while(zeros < input58.length && input58[zeros] == 0) {
            zeros++;
        }
        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;
        for(int inputStart = zeros; inputStart < input58.length; ) {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
            if(input58[inputStart] == 0) {
                inputStart++;
            }
        }
        while(outputStart < decoded.length && decoded[outputStart] == 0) {
            outputStart++;
        }
        byte[] result = Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length);
        Arrays.fill(decoded, (byte)0);
        return result;
    }

    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for(int i = firstDigit; i < number.length; i++) {
            int digit = (int)number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte)(temp / divisor);
            remainder = temp % divisor;
        }
        return (byte)remainder;
    }

    private static byte[] doubleSha256(byte[] input) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            return sha.digest(sha.digest(input));
        } catch(NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
