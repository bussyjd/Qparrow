// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BtqPsbtSignerTest {
    private static final byte[] MASTER = master();
    private static final BtqP2mrKeyPath.Address INPUT = BtqP2mrKeyPath.derive(
            MASTER, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 0);
    private static final BtqP2mrKeyPath.Address PAYMENT = BtqP2mrKeyPath.derive(
            MASTER, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 7);
    private static final BtqP2mrKeyPath.Address CHANGE = BtqP2mrKeyPath.derive(
            MASTER, BtqNetwork.REGTEST, BtqCustodySpec.Chain.CHANGE, 0);
    private static final String TXID = "201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201";

    @Test
    void signsOnlyTheExactP2mrSpendIntent() {
        String psbt = psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000);
        BtqPsbtSigner.Review review = BtqPsbtSigner.review(psbt, MASTER, BtqNetwork.REGTEST,
                List.of(input(BtqCustodySpec.Chain.RECEIVE, 0)), intent(1_000));
        assertEquals(1_000, review.feeSats());
        assertFalse(containsSignature(psbt), "review must not create a signature");

        BtqPsbtSigner.SignedPsbt signed = BtqPsbtSigner.sign(psbt, MASTER, BtqNetwork.REGTEST,
                List.of(input(BtqCustodySpec.Chain.RECEIVE, 0)), intent(1_000));

        assertEquals(1_000, signed.feeSats());
        assertEquals(64, signed.expectedTxid().length());
        assertEquals(List.of("f9b97b056f367527182a9c536fb2d93951c5de840d190ceaa9a35306f9e79053"), signed.sighashes());
        byte[] signedBytes = Base64.getDecoder().decode(signed.base64());
        byte[] signatureKeyPrefix = concat(new byte[]{0x1b}, INPUT.publicKey(), INPUT.merkleRoot());
        assertTrue(indexOf(signedBytes, signatureKeyPrefix) >= 0,
                "signed PSBT must use BTQ's 0x1b | 1312-byte pubkey | leaf-hash key");

        BtqPsbtSigner.FinalizedTransaction finalized = BtqPsbtSigner.finalizeTransaction(signed);
        assertEquals(signed.expectedTxid(), finalized.txid());
        assertEquals(finalized.txid(), BtqPsbtSigner.finalizedTransactionId(finalized.hex()));
        assertEquals(finalized.wtxid(), BtqPsbtSigner.finalizedWitnessTransactionId(finalized.hex()));
        assertTrue(finalized.hex().contains("03fd7509"),
                "local witness must contain exactly three items followed by the 2421-byte signature");
        int signatureStart = finalized.hex().indexOf("03fd7509") + "03fd7509".length();
        String mutatedWitness = finalized.hex().substring(0, signatureStart)
                + (finalized.hex().substring(signatureStart, signatureStart + 2).equals("00") ? "01" : "00")
                + finalized.hex().substring(signatureStart + 2);
        assertEquals(finalized.txid(), BtqPsbtSigner.finalizedTransactionId(mutatedWitness));
        assertNotEquals(finalized.wtxid(), BtqPsbtSigner.finalizedWitnessTransactionId(mutatedWitness));
    }

    @Test
    void rejectsFeeAboveTheUserCeiling() {
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.sign(
                psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000),
                MASTER, BtqNetwork.REGTEST,
                List.of(input(BtqCustodySpec.Chain.RECEIVE, 0)), intent(999)));
    }

    @Test
    void rejectsNodeSubstitutionOfInputTreeOrKey() {
        byte[] wrongRoot = INPUT.merkleRoot();
        wrongRoot[0] ^= 1;
        String psbt = psbt(wrongRoot, PAYMENT.scriptPubKey(), 50_000, 49_000);
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.sign(
                psbt, MASTER, BtqNetwork.REGTEST,
                List.of(input(BtqCustodySpec.Chain.RECEIVE, 0)), intent(1_000)));

        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.sign(
                psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000),
                MASTER, BtqNetwork.REGTEST,
                List.of(input(BtqCustodySpec.Chain.RECEIVE, 1)), intent(1_000)));
    }

    @Test
    void rejectsClassicalOrUnapprovedOutputs() {
        byte[] classical = {0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        String psbt = psbt(INPUT.merkleRoot(), classical, 50_000, 49_000);
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.sign(
                psbt, MASTER, BtqNetwork.REGTEST,
                List.of(input(BtqCustodySpec.Chain.RECEIVE, 0)), intent(1_000)));

        String changedPayment = psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_001, 48_999);
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.sign(
                changedPayment, MASTER, BtqNetwork.REGTEST,
                List.of(input(BtqCustodySpec.Chain.RECEIVE, 0)), intent(1_000)));
    }

    @Test
    void rejectsNodeSubstitutionOfAnOtherwiseOwnedOutpoint() {
        BtqPsbtSigner.Input substituted = new BtqPsbtSigner.Input(
                "ff".repeat(32), 3, 100_000, BtqCustodySpec.Chain.RECEIVE, 0);
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.sign(
                psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000),
                MASTER, BtqNetwork.REGTEST, List.of(substituted), intent(1_000)));
    }

    @Test
    void resolvesShuffledCoreInputsByExactOutpointAndAmount() {
        BtqP2mrKeyPath.Address second = BtqP2mrKeyPath.derive(
                MASTER, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 1);
        String secondTxid = "403f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221";
        BtqSpendIntent twoInputIntent = new BtqSpendIntent(
                List.of(new BtqSpendIntent.Payment(PAYMENT.scriptPubKey(), 50_000)),
                CHANGE.scriptPubKey(), 1_000);
        List<BtqPsbtSigner.Input> approvals = List.of(
                new BtqPsbtSigner.Input(TXID, 3, 100_000, BtqCustodySpec.Chain.RECEIVE, 0),
                new BtqPsbtSigner.Input(secondTxid, 5, 100_000, BtqCustodySpec.Chain.RECEIVE, 1));

        BtqPsbtSigner.SignedPsbt signed = BtqPsbtSigner.sign(
                reversedTwoInputPsbt(second), MASTER, BtqNetwork.REGTEST, approvals, twoInputIntent);

        assertEquals(2, signed.sighashes().size());
        BtqPsbtSigner.FinalizedTransaction finalized = BtqPsbtSigner.finalizeTransaction(signed);
        assertEquals(signed.expectedTxid(), finalized.txid());
    }

    @Test
    void rejectsNodeSubstitutionOfSelectedCoinAmount() {
        String changedAmount = psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000,
                100_001, List.of());
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                changedAmount, MASTER, BtqNetwork.REGTEST,
                List.of(input(BtqCustodySpec.Chain.RECEIVE, 0)), intent(2_000)));
    }

    @Test
    void rejectsAProposalAboveBtqStandardTransactionWeightBeforeKeyUse() {
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                oversizedInputCountPsbt(91), MASTER, BtqNetwork.REGTEST,
                java.util.Collections.nCopies(91, input(BtqCustodySpec.Chain.RECEIVE, 0)), intent(1_000)));
    }

    @Test
    void rejectsMalformedFinalizedPresignedWrongSighashAndVersionPsbt() {
        List<BtqPsbtSigner.Input> inputs = List.of(input(BtqCustodySpec.Chain.RECEIVE, 0));
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                withInputFields(new TestField(new byte[]{0x07}, new byte[]{0x00})), MASTER,
                BtqNetwork.REGTEST, inputs, intent(1_000)));
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                withInputFields(new TestField(new byte[]{0x1b}, new byte[]{0x00})), MASTER,
                BtqNetwork.REGTEST, inputs, intent(1_000)));
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                withInputFields(new TestField(new byte[]{0x03}, new byte[]{0x02, 0, 0, 0})), MASTER,
                BtqNetwork.REGTEST, inputs, intent(1_000)));

        byte[] wrongVersion = Base64.getDecoder().decode(
                psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000));
        wrongVersion[8] = 3;
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                Base64.getEncoder().encodeToString(wrongVersion), MASTER, BtqNetwork.REGTEST,
                inputs, intent(1_000)));

        byte[] valid = Base64.getDecoder().decode(
                psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000));
        byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                Base64.getEncoder().encodeToString(trailing), MASTER, BtqNetwork.REGTEST,
                inputs, intent(1_000)));
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000), MASTER,
                BtqNetwork.REGTEST, List.of(), intent(1_000)));

        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                withInputFields(new TestField(new byte[]{(byte)0xfc}, new byte[]{0x01})), MASTER,
                BtqNetwork.REGTEST, inputs, intent(1_000)),
                "unsupported/proprietary PSBT fields must not be preserved");

        String canonical = psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000);
        assertTrue(canonical.endsWith("="));
        assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                canonical.substring(0, canonical.length() - 1), MASTER,
                BtqNetwork.REGTEST, inputs, intent(1_000)));

        for(byte[] nonCanonicalLength : List.of(
                new byte[]{(byte)0xfd, (byte)0xfc, 0x00},
                new byte[]{(byte)0xfe, (byte)0xff, (byte)0xff, 0x00, 0x00},
                new byte[]{(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 0, 0, 0, 0})) {
            assertThrows(IllegalArgumentException.class, () -> BtqPsbtSigner.review(
                    replaceFirstKeyLength(canonical, nonCanonicalLength), MASTER,
                    BtqNetwork.REGTEST, inputs, intent(1_000)));
        }
    }

    private static BtqPsbtSigner.Input input(BtqCustodySpec.Chain chain, int index) {
        return new BtqPsbtSigner.Input(TXID, 3, 100_000, chain, index);
    }

    private static BtqSpendIntent intent(long maximumFee) {
        return new BtqSpendIntent(
                List.of(new BtqSpendIntent.Payment(PAYMENT.scriptPubKey(), 50_000)),
                CHANGE.scriptPubKey(), maximumFee);
    }

    private static String psbt(byte[] metadataRoot, byte[] paymentScript, long paymentAmount, long changeAmount) {
        return psbt(metadataRoot, paymentScript, paymentAmount, changeAmount, List.of());
    }

    private static String withInputFields(TestField... fields) {
        return psbt(INPUT.merkleRoot(), PAYMENT.scriptPubKey(), 50_000, 49_000, List.of(fields));
    }

    private static String psbt(byte[] metadataRoot, byte[] paymentScript, long paymentAmount,
                               long changeAmount, List<TestField> extraInputFields) {
        return psbt(metadataRoot, paymentScript, paymentAmount, changeAmount, 100_000, extraInputFields);
    }

    private static String psbt(byte[] metadataRoot, byte[] paymentScript, long paymentAmount,
                               long changeAmount, long witnessAmount, List<TestField> extraInputFields) {
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
        txOut(transaction, paymentAmount, paymentScript);
        txOut(transaction, changeAmount, CHANGE.scriptPubKey());
        writeLe(transaction, 0, 4);

        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        encoded.writeBytes(new byte[]{'p', 's', 'b', 't', (byte)0xff});
        field(encoded, new byte[]{0x00}, transaction.toByteArray());
        encoded.write(0);

        ByteArrayOutputStream witnessUtxo = new ByteArrayOutputStream();
        txOut(witnessUtxo, witnessAmount, INPUT.scriptPubKey());
        field(encoded, new byte[]{0x01}, witnessUtxo.toByteArray());
        field(encoded, new byte[]{0x19, (byte)BtqP2mrKeyPath.CONTROL_BYTE},
                concat(INPUT.leafScript(), new byte[]{(byte)BtqP2mrKeyPath.LEAF_VERSION}));
        field(encoded, new byte[]{0x1a}, metadataRoot);
        for(TestField extra : extraInputFields) field(encoded, extra.key(), extra.value());
        encoded.write(0);
        encoded.write(0);
        encoded.write(0);
        return Base64.getEncoder().encodeToString(encoded.toByteArray());
    }

    private static String reversedTwoInputPsbt(BtqP2mrKeyPath.Address second) {
        ByteArrayOutputStream transaction = new ByteArrayOutputStream();
        writeLe(transaction, 2, 4);
        compact(transaction, 2);
        byte[] secondWireTxid = new byte[32];
        for(int i = 0; i < secondWireTxid.length; i++) secondWireTxid[i] = (byte)(0x21 + i);
        transaction.writeBytes(secondWireTxid);
        writeLe(transaction, 5, 4);
        compact(transaction, 0);
        writeLe(transaction, 0xfffffffdL, 4);
        byte[] firstWireTxid = new byte[32];
        for(int i = 0; i < firstWireTxid.length; i++) firstWireTxid[i] = (byte)(i + 1);
        transaction.writeBytes(firstWireTxid);
        writeLe(transaction, 3, 4);
        compact(transaction, 0);
        writeLe(transaction, 0xfffffffdL, 4);
        compact(transaction, 2);
        txOut(transaction, 50_000, PAYMENT.scriptPubKey());
        txOut(transaction, 149_000, CHANGE.scriptPubKey());
        writeLe(transaction, 0, 4);

        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        encoded.writeBytes(new byte[]{'p', 's', 'b', 't', (byte)0xff});
        field(encoded, new byte[]{0x00}, transaction.toByteArray());
        encoded.write(0);
        appendInputMap(encoded, second);
        appendInputMap(encoded, INPUT);
        encoded.write(0);
        encoded.write(0);
        return Base64.getEncoder().encodeToString(encoded.toByteArray());
    }

    private static void appendInputMap(ByteArrayOutputStream encoded, BtqP2mrKeyPath.Address address) {
        ByteArrayOutputStream witnessUtxo = new ByteArrayOutputStream();
        txOut(witnessUtxo, 100_000, address.scriptPubKey());
        field(encoded, new byte[]{0x01}, witnessUtxo.toByteArray());
        field(encoded, new byte[]{0x19, (byte)BtqP2mrKeyPath.CONTROL_BYTE},
                concat(address.leafScript(), new byte[]{(byte)BtqP2mrKeyPath.LEAF_VERSION}));
        field(encoded, new byte[]{0x1a}, address.merkleRoot());
        encoded.write(0);
    }

    private static String oversizedInputCountPsbt(int inputCount) {
        ByteArrayOutputStream transaction = new ByteArrayOutputStream();
        writeLe(transaction, 2, 4);
        compact(transaction, inputCount);
        for(int input = 0; input < inputCount; input++) {
            byte[] txid = new byte[32];
            txid[0] = (byte)input;
            transaction.writeBytes(txid);
            writeLe(transaction, input, 4);
            compact(transaction, 0);
            writeLe(transaction, 0xfffffffdL, 4);
        }
        compact(transaction, 1);
        txOut(transaction, 50_000, PAYMENT.scriptPubKey());
        writeLe(transaction, 0, 4);

        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        encoded.writeBytes(new byte[]{'p', 's', 'b', 't', (byte)0xff});
        field(encoded, new byte[]{0x00}, transaction.toByteArray());
        encoded.write(0);
        for(int input = 0; input < inputCount; input++) encoded.write(0);
        encoded.write(0);
        return Base64.getEncoder().encodeToString(encoded.toByteArray());
    }

    private static String replaceFirstKeyLength(String canonical, byte[] replacement) {
        byte[] valid = Base64.getDecoder().decode(canonical);
        byte[] malformed = new byte[valid.length - 1 + replacement.length];
        System.arraycopy(valid, 0, malformed, 0, 5);
        System.arraycopy(replacement, 0, malformed, 5, replacement.length);
        System.arraycopy(valid, 6, malformed, 5 + replacement.length, valid.length - 6);
        return Base64.getEncoder().encodeToString(malformed);
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

    private static boolean containsSignature(String psbt) {
        byte[] encoded = Base64.getDecoder().decode(psbt);
        return indexOf(encoded, concat(new byte[]{0x1b}, INPUT.publicKey(), INPUT.merkleRoot())) >= 0;
    }

    private static byte[] master() {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) master[i] = (byte)i;
        return master;
    }

    private record TestField(byte[] key, byte[] value) {
    }
}
