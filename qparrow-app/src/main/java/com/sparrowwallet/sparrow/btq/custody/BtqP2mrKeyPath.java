// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import com.sparrowwallet.sparrow.btq.BtqP2mrAddressCodec;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/** Builds Qparrow's only output policy: one ML-DSA-44 key in one P2MR leaf. */
public final class BtqP2mrKeyPath {
    public static final int LEAF_VERSION = 0xc0;
    public static final int CONTROL_BYTE = 0xc1;
    public static final int OP_PUSHDATA2 = 0x4d;
    public static final int OP_CHECKSIGDILITHIUM = 0xbb;

    private static final byte[] TAP_LEAF_TAG = sha256("TapLeaf".getBytes(java.nio.charset.StandardCharsets.US_ASCII));

    private BtqP2mrKeyPath() {
    }

    public static Address derive(byte[] masterSecret, BtqNetwork network, BtqCustodySpec.Chain chain, int index) {
        byte[] keySeed = BtqCustodySpec.deriveKeySeed(masterSecret, network, chain, index);
        try {
            return fromPublicKey(network, chain, index, BtqMldsa44.publicKeyFromSeed(keySeed));
        } finally {
            Arrays.fill(keySeed, (byte)0);
        }
    }

    public static Address fromPublicKey(BtqNetwork network, BtqCustodySpec.Chain chain, int index, byte[] publicKey) {
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(chain, "chain");
        if(index < 0 || index > BtqCustodySpec.MAX_INDEX) {
            throw new IllegalArgumentException("derivation index out of range");
        }
        BtqCustodySpec.requireLength(publicKey, BtqMldsa44.PUBLIC_KEY_BYTES, "ML-DSA public key");

        byte[] leafScript = singleKeyLeaf(publicKey);
        byte[] merkleRoot = tapLeafHash(leafScript);
        byte[] controlBlock = {(byte)CONTROL_BYTE};
        byte[] scriptPubKey = new byte[34];
        scriptPubKey[0] = 0x52; // OP_2 / witness version 2
        scriptPubKey[1] = 0x20; // push 32-byte program
        System.arraycopy(merkleRoot, 0, scriptPubKey, 2, merkleRoot.length);
        String address = BtqP2mrAddressCodec.encode(network, HexFormat.of().formatHex(merkleRoot));

        return new Address(network, chain, index, publicKey, leafScript, merkleRoot, controlBlock, scriptPubKey, address);
    }

    static byte[] singleKeyLeaf(byte[] publicKey) {
        BtqCustodySpec.requireLength(publicKey, BtqMldsa44.PUBLIC_KEY_BYTES, "ML-DSA public key");
        ByteArrayOutputStream script = new ByteArrayOutputStream(BtqMldsa44.PUBLIC_KEY_BYTES + 4);
        script.write(OP_PUSHDATA2);
        script.write(BtqMldsa44.PUBLIC_KEY_BYTES & 0xff);
        script.write((BtqMldsa44.PUBLIC_KEY_BYTES >>> 8) & 0xff);
        script.writeBytes(publicKey);
        script.write(OP_CHECKSIGDILITHIUM);
        return script.toByteArray();
    }

    static byte[] tapLeafHash(byte[] script) {
        Objects.requireNonNull(script, "script");
        ByteArrayOutputStream encoded = new ByteArrayOutputStream(script.length + 4);
        encoded.write(LEAF_VERSION);
        writeCompactSize(encoded, script.length);
        encoded.writeBytes(script);

        MessageDigest digest = sha256Digest();
        digest.update(TAP_LEAF_TAG);
        digest.update(TAP_LEAF_TAG);
        return digest.digest(encoded.toByteArray());
    }

    private static void writeCompactSize(ByteArrayOutputStream output, long value) {
        if(value < 0) {
            throw new IllegalArgumentException("negative compact size");
        }
        if(value < 253) {
            output.write((int)value);
        } else if(value <= 0xffffL) {
            output.write(253);
            output.write((int)(value & 0xff));
            output.write((int)((value >>> 8) & 0xff));
        } else {
            throw new IllegalArgumentException("P2MR leaf is unexpectedly large");
        }
    }

    private static byte[] sha256(byte[] input) {
        return sha256Digest().digest(input);
    }

    private static MessageDigest sha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch(NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    public static final class Address {
        private final BtqNetwork network;
        private final BtqCustodySpec.Chain chain;
        private final int index;
        private final byte[] publicKey;
        private final byte[] leafScript;
        private final byte[] merkleRoot;
        private final byte[] controlBlock;
        private final byte[] scriptPubKey;
        private final String address;

        private Address(BtqNetwork network, BtqCustodySpec.Chain chain, int index, byte[] publicKey,
                        byte[] leafScript, byte[] merkleRoot, byte[] controlBlock, byte[] scriptPubKey,
                        String address) {
            this.network = network;
            this.chain = chain;
            this.index = index;
            this.publicKey = publicKey.clone();
            this.leafScript = leafScript.clone();
            this.merkleRoot = merkleRoot.clone();
            this.controlBlock = controlBlock.clone();
            this.scriptPubKey = scriptPubKey.clone();
            this.address = address;
        }

        public BtqNetwork network() {
            return network;
        }

        public BtqCustodySpec.Chain chain() {
            return chain;
        }

        public int index() {
            return index;
        }

        public byte[] publicKey() {
            return publicKey.clone();
        }

        public byte[] leafScript() {
            return leafScript.clone();
        }

        public byte[] merkleRoot() {
            return merkleRoot.clone();
        }

        public byte[] controlBlock() {
            return controlBlock.clone();
        }

        public byte[] scriptPubKey() {
            return scriptPubKey.clone();
        }

        public String address() {
            return address;
        }
    }
}
