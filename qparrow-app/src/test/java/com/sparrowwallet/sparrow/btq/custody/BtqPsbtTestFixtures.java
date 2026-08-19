// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

final class BtqPsbtTestFixtures {
    private static final byte[] MASTER = master();
    private static final BtqP2mrKeyPath.Address INPUT = BtqP2mrKeyPath.derive(
            MASTER, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 0);
    private static final BtqP2mrKeyPath.Address PAYMENT = BtqP2mrKeyPath.derive(
            MASTER, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 7);
    private static final BtqP2mrKeyPath.Address CHANGE = BtqP2mrKeyPath.derive(
            MASTER, BtqNetwork.REGTEST, BtqCustodySpec.Chain.CHANGE, 0);
    private static final String TXID = "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201";

    private BtqPsbtTestFixtures() {
    }

    static BtqPsbtSigner.SignedPsbt signed() {
        return BtqPsbtSigner.sign(psbt(), MASTER, BtqNetwork.REGTEST,
                List.of(new BtqPsbtSigner.Input(TXID, 3, 100_000, BtqCustodySpec.Chain.RECEIVE, 0)),
                new BtqSpendIntent(
                        List.of(new BtqSpendIntent.Payment(PAYMENT.scriptPubKey(), 50_000)),
                        CHANGE.scriptPubKey(), 1_000));
    }

    static BtqPsbtSigner.SignedPsbt withTamperedSignature(BtqPsbtSigner.SignedPsbt signed) {
        byte[] encoded = Base64.getDecoder().decode(signed.base64());
        byte[] key = concat(new byte[]{0x1b}, INPUT.publicKey(), INPUT.merkleRoot());
        int keyOffset = indexOf(encoded, key);
        if(keyOffset < 0) throw new AssertionError("missing P2MR signature key");
        int valueLengthOffset = keyOffset + key.length;
        if((encoded[valueLengthOffset] & 0xff) != 253) throw new AssertionError("unexpected signature length encoding");
        encoded[valueLengthOffset + 3 + 100] ^= 1;
        return new BtqPsbtSigner.SignedPsbt(Base64.getEncoder().encodeToString(encoded),
                signed.feeSats(), signed.sighashes(), signed.expectedTxid());
    }

    private static String psbt() {
        ByteArrayOutputStream transaction = new ByteArrayOutputStream();
        writeLe(transaction, 2, 4);
        compact(transaction, 1);
        byte[] txid = new byte[32];
        for(int i = 0; i < txid.length; i++) txid[i] = (byte)(i + 1);
        transaction.writeBytes(txid);
        writeLe(transaction, 3, 4);
        compact(transaction, 0);
        writeLe(transaction, 0xfffffffdL, 4);
        compact(transaction, 2);
        txOut(transaction, 50_000, PAYMENT.scriptPubKey());
        txOut(transaction, 49_000, CHANGE.scriptPubKey());
        writeLe(transaction, 0, 4);

        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        encoded.writeBytes(new byte[]{'p', 's', 'b', 't', (byte)0xff});
        field(encoded, new byte[]{0x00}, transaction.toByteArray());
        encoded.write(0);
        ByteArrayOutputStream witnessUtxo = new ByteArrayOutputStream();
        txOut(witnessUtxo, 100_000, INPUT.scriptPubKey());
        field(encoded, new byte[]{0x01}, witnessUtxo.toByteArray());
        field(encoded, new byte[]{0x19, (byte)BtqP2mrKeyPath.CONTROL_BYTE},
                concat(INPUT.leafScript(), new byte[]{(byte)BtqP2mrKeyPath.LEAF_VERSION}));
        field(encoded, new byte[]{0x1a}, INPUT.merkleRoot());
        encoded.write(0);
        encoded.write(0);
        encoded.write(0);
        return Base64.getEncoder().encodeToString(encoded.toByteArray());
    }

    private static void txOut(ByteArrayOutputStream output, long amount, byte[] script) {
        writeLe(output, amount, 8);
        compact(output, script.length);
        output.writeBytes(script);
    }

    private static void field(ByteArrayOutputStream output, byte[] key, byte[] value) {
        compact(output, key.length);
        output.writeBytes(key);
        compact(output, value.length);
        output.writeBytes(value);
    }

    private static void compact(ByteArrayOutputStream output, long value) {
        if(value < 253) {
            output.write((int)value);
        } else if(value <= 0xffff) {
            output.write(253);
            writeLe(output, value, 2);
        } else {
            throw new IllegalArgumentException("test compact size is too large");
        }
    }

    private static void writeLe(ByteArrayOutputStream output, long value, int bytes) {
        for(int i = 0; i < bytes; i++) output.write((int)(value >>> (8 * i)) & 0xff);
    }

    private static byte[] concat(byte[]... values) {
        int length = Arrays.stream(values).mapToInt(value -> value.length).sum();
        byte[] result = new byte[length];
        int offset = 0;
        for(byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer: for(int i = 0; i <= haystack.length - needle.length; i++) {
            for(int j = 0; j < needle.length; j++) {
                if(haystack[i + j] != needle[j]) continue outer;
            }
            return i;
        }
        return -1;
    }

    private static byte[] master() {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) master[i] = (byte)i;
        return master;
    }
}
