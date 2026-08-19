// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Qparrow's deliberately small, versioned BTQ custody format.
 *
 * <p>This is a new-wallet format. It does not import or reproduce BTQ Core
 * descriptor wallets, historical Dilithium destinations, Bitcoin BIP32 keys,
 * or Sparrow keystores. A wallet contains one 32-byte master secret and derives
 * independent receive/change ML-DSA seeds through HKDF-SHA512.</p>
 */
public final class BtqCustodySpec {
    public static final String FORMAT = "qparrow-btq-custody";
    public static final int VERSION = 1;
    public static final int MASTER_SECRET_BYTES = 32;
    public static final int MAX_INDEX = 0x7fffffff;

    private static final byte[] HKDF_SALT = "Qparrow/BTQ/Custody/v1"
            .getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEY_INFO = "ML-DSA-44/P2MR"
            .getBytes(StandardCharsets.US_ASCII);

    private BtqCustodySpec() {
    }

    public enum Chain {
        RECEIVE(0),
        CHANGE(1);

        private final int id;

        Chain(int id) {
            this.id = id;
        }
    }

    /**
     * Derive one 32-byte ML-DSA key-generation seed.
     *
     * <p>The network is intentionally bound into derivation. A development
     * backup cannot silently become a mainnet wallet, and the wallet file does
     * not need compatibility paths for Bitcoin or earlier Qparrow prototypes.</p>
     */
    public static byte[] deriveKeySeed(byte[] masterSecret, BtqNetwork network, Chain chain, int index) {
        requireLength(masterSecret, MASTER_SECRET_BYTES, "master secret");
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(chain, "chain");
        if(index < 0 || index > MAX_INDEX) {
            throw new IllegalArgumentException("derivation index must be between 0 and " + MAX_INDEX);
        }

        byte[] prk = hmacSha512(HKDF_SALT, masterSecret);
        byte[] networkId = network.rpcChain().getBytes(StandardCharsets.US_ASCII);
        ByteBuffer info = ByteBuffer.allocate(KEY_INFO.length + 1 + networkId.length + 1 + Integer.BYTES + 1);
        info.put(KEY_INFO);
        info.put((byte)0);
        info.put(networkId);
        info.put((byte)chain.id);
        info.putInt(index);
        info.put((byte)1); // RFC 5869 first expand block

        byte[] expanded = null;
        try {
            expanded = hmacSha512(prk, info.array());
            return Arrays.copyOf(expanded, BtqMldsa44.SEED_BYTES);
        } finally {
            Arrays.fill(prk, (byte)0);
            if(expanded != null) {
                Arrays.fill(expanded, (byte)0);
            }
            Arrays.fill(info.array(), (byte)0);
        }
    }

    private static byte[] hmacSha512(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA512");
            mac.init(new SecretKeySpec(key, "HmacSHA512"));
            return mac.doFinal(data);
        } catch(GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA512 is unavailable", e);
        }
    }

    static void requireLength(byte[] bytes, int expected, String name) {
        if(bytes == null || bytes.length != expected) {
            throw new IllegalArgumentException(name + " must be exactly " + expected + " bytes");
        }
    }
}
