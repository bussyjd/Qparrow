// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Strict PSBT-v0 validator and signer for Qparrow's single-key ML-DSA P2MR policy.
 *
 * <p>This deliberately does not adapt Drongo's Bitcoin PSBT model and has no
 * legacy-key, Taproot, multisig, or migration mode. It only signs a transaction
 * when every input is a caller-identified Qparrow key and every output is P2MR.</p>
 */
public final class BtqPsbtSigner {
    public static final int MAX_SIGNING_INPUTS = 128;
    public static final int MAX_OUTPUTS = 128;
    private static final int MAX_FINALIZED_TRANSACTION_BYTES = 4_000_000;
    private static final long MAX_MONEY_SATS = 21_000_000L * 100_000_000L;
    private static final HexFormat HEX = HexFormat.of();

    private static final byte[] MAGIC = {(byte)'p', (byte)'s', (byte)'b', (byte)'t', (byte)0xff};
    private static final int PSBT_GLOBAL_UNSIGNED_TX = 0x00;
    private static final int PSBT_GLOBAL_VERSION = 0xfb;
    private static final int PSBT_IN_WITNESS_UTXO = 0x01;
    private static final int PSBT_IN_SIGHASH_TYPE = 0x03;
    private static final int PSBT_IN_FINAL_SCRIPTSIG = 0x07;
    private static final int PSBT_IN_FINAL_SCRIPTWITNESS = 0x08;
    private static final int PSBT_IN_P2MR_LEAF_SCRIPT = 0x19;
    private static final int PSBT_IN_P2MR_MERKLE_ROOT = 0x1a;
    private static final int PSBT_IN_P2MR_DILITHIUM_SCRIPT_SIG = 0x1b;
    private static final byte[] TAP_SIGHASH_TAG = sha256("TapSighash".getBytes(java.nio.charset.StandardCharsets.US_ASCII));

    private BtqPsbtSigner() {
    }

    public record Input(String txid, int vout, BtqCustodySpec.Chain chain, int index) {
        public Input {
            if(txid == null || !txid.matches("[0-9a-fA-F]{64}")) {
                throw new IllegalArgumentException("input transaction id must be 32-byte hexadecimal");
            }
            if(vout < 0) throw new IllegalArgumentException("input output index cannot be negative");
            Objects.requireNonNull(chain, "chain");
            if(index < 0 || index > BtqCustodySpec.MAX_INDEX) {
                throw new IllegalArgumentException("key index out of range");
            }
        }
    }

    public record SignedPsbt(String base64, long feeSats, List<String> sighashes, String expectedTxid) {
        public SignedPsbt {
            Objects.requireNonNull(base64, "base64");
            sighashes = List.copyOf(sighashes);
            if(expectedTxid == null || !expectedTxid.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("expected transaction id must be lowercase 32-byte hexadecimal");
            }
        }
    }

    public record Review(long feeSats) {
    }

    public static SignedPsbt sign(String base64Psbt, byte[] masterSecret, BtqNetwork network,
                                  List<Input> approvedInputs, BtqSpendIntent intent) {
        Processed processed = process(base64Psbt, masterSecret, network, approvedInputs, intent, true);
        return new SignedPsbt(processed.base64, processed.feeSats, processed.sighashes, processed.expectedTxid);
    }

    /** Fully validate the exact PSBT and approved intent without creating any signature. */
    public static Review review(String base64Psbt, byte[] masterSecret, BtqNetwork network,
                                List<Input> approvedInputs, BtqSpendIntent intent) {
        Processed processed = process(base64Psbt, masterSecret, network, approvedInputs, intent, false);
        return new Review(processed.feeSats);
    }

    private static Processed process(String base64Psbt, byte[] masterSecret, BtqNetwork network,
                                     List<Input> approvedInputs, BtqSpendIntent intent, boolean createSignatures) {
        BtqCustodySpec.requireLength(masterSecret, BtqCustodySpec.MASTER_SECRET_BYTES, "master secret");
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(approvedInputs, "approved inputs");
        Objects.requireNonNull(intent, "intent");

        byte[] encoded;
        try {
            encoded = Base64.getDecoder().decode(Objects.requireNonNull(base64Psbt, "PSBT"));
        } catch(IllegalArgumentException e) {
            throw new IllegalArgumentException("PSBT is not canonical base64", e);
        }
        if(encoded.length > 8 * 1024 * 1024) {
            throw new IllegalArgumentException("PSBT exceeds the Qparrow signing limit");
        }

        Psbt psbt = parsePsbt(encoded);
        Transaction tx = parseUnsignedTransaction(psbt.unsignedTransaction);
        if(tx.inputs.size() != approvedInputs.size()) {
            throw new IllegalArgumentException("one approved Qparrow outpoint and key is required for every input");
        }
        if(tx.inputs.isEmpty() || tx.inputs.size() > MAX_SIGNING_INPUTS) {
            throw new IllegalArgumentException("unsupported input count");
        }
        if(tx.outputs.isEmpty() || tx.outputs.size() > MAX_OUTPUTS) {
            throw new IllegalArgumentException("unsupported output count");
        }

        List<TxOut> spentOutputs = new ArrayList<>(tx.inputs.size());
        List<SigningInput> signingInputs = new ArrayList<>(tx.inputs.size());
        Set<String> seenOutpoints = new HashSet<>();
        try {
          for(int i = 0; i < tx.inputs.size(); i++) {
            MapData inputMap = psbt.inputMaps.get(i);
            if(inputMap.hasType(PSBT_IN_FINAL_SCRIPTSIG) || inputMap.hasType(PSBT_IN_FINAL_SCRIPTWITNESS)) {
                throw new IllegalArgumentException("input " + i + " is already finalized");
            }
            if(inputMap.hasType(PSBT_IN_P2MR_DILITHIUM_SCRIPT_SIG)) {
                throw new IllegalArgumentException("input " + i + " already contains a P2MR signature");
            }
            MapEntry sighashEntry = inputMap.singleType(PSBT_IN_SIGHASH_TYPE, false, i);
            if(sighashEntry != null && (sighashEntry.key.length != 1 || sighashEntry.value.length != 4
                    || readUint32(sighashEntry.value, 0) != BtqMldsa44.SIGHASH_ALL)) {
                throw new IllegalArgumentException("input " + i + " does not use SIGHASH_ALL");
            }

            MapEntry witnessEntry = inputMap.singleType(PSBT_IN_WITNESS_UTXO, true, i);
            if(witnessEntry.key.length != 1) {
                throw new IllegalArgumentException("input " + i + " has a malformed witness UTXO key");
            }
            TxOut spentOutput = parseTxOut(witnessEntry.value, "input " + i + " witness UTXO");
            spentOutputs.add(spentOutput);

            Input approved = approvedInputs.get(i);
            TxIn transactionInput = tx.inputs.get(i);
            String transactionTxid = wireTxidHex(transactionInput.txid);
            if(transactionInput.vout != approved.vout()
                    || !transactionTxid.equalsIgnoreCase(approved.txid())) {
                throw new IllegalArgumentException("input " + i + " is not the approved outpoint");
            }
            if(!seenOutpoints.add(transactionTxid + ':' + transactionInput.vout)) {
                throw new IllegalArgumentException("transaction contains a duplicate input outpoint");
            }
            Input locator = approved;
            byte[] keySeed = BtqCustodySpec.deriveKeySeed(masterSecret, network, locator.chain(), locator.index());
            try {
                BtqP2mrKeyPath.Address address = BtqP2mrKeyPath.fromPublicKey(network, locator.chain(), locator.index(),
                        BtqMldsa44.publicKeyFromSeed(keySeed));
                if(!Arrays.equals(spentOutput.scriptPubKey, address.scriptPubKey())) {
                    throw new IllegalArgumentException("input " + i + " witness UTXO is not the selected Qparrow key");
                }
                validateP2mrMetadata(inputMap, address, i);
                signingInputs.add(new SigningInput(keySeed.clone(), address));
            } finally {
                Arrays.fill(keySeed, (byte)0);
            }
          }

            long fee = validateIntent(spentOutputs, tx.outputs, intent);
            List<String> sighashes = new ArrayList<>(createSignatures ? tx.inputs.size() : 0);
            if(createSignatures) {
                for(int i = 0; i < tx.inputs.size(); i++) {
                    SigningInput signingInput = signingInputs.get(i);
                    byte[] sighash = signatureHash(tx, spentOutputs, i, signingInput.address.leafScript());
                    byte[] signature = BtqMldsa44.signTransactionHash(signingInput.keySeed, sighash);
                    if(!BtqMldsa44.verifyTransactionHash(signingInput.address.publicKey(), sighash, signature)) {
                        throw new IllegalStateException("local ML-DSA verification failed for input " + i);
                    }
                    byte[] signatureKey = concat(new byte[]{(byte)PSBT_IN_P2MR_DILITHIUM_SCRIPT_SIG},
                            signingInput.address.publicKey(), signingInput.address.merkleRoot());
                    psbt.inputMaps.get(i).add(new MapEntry(signatureKey, signature));
                    sighashes.add(HexFormat.of().formatHex(sighash));
                }
            }
            String expectedTxid = wireTxidHex(sha256(sha256(psbt.unsignedTransaction)));
            return new Processed(Base64.getEncoder().encodeToString(serializePsbt(psbt)), fee,
                    List.copyOf(sighashes), expectedTxid);
        } finally {
            for(SigningInput input : signingInputs) {
                Arrays.fill(input.keySeed, (byte)0);
            }
        }
    }

    private static void validateP2mrMetadata(MapData inputMap, BtqP2mrKeyPath.Address address, int inputIndex) {
        MapEntry leaf = inputMap.singleType(PSBT_IN_P2MR_LEAF_SCRIPT, true, inputIndex);
        byte[] expectedControl = address.controlBlock();
        if(leaf.key.length != 1 + expectedControl.length
                || !Arrays.equals(Arrays.copyOfRange(leaf.key, 1, leaf.key.length), expectedControl)) {
            throw new IllegalArgumentException("input " + inputIndex + " does not carry the exact Qparrow control block");
        }
        byte[] expectedLeafValue = concat(address.leafScript(), new byte[]{(byte)BtqP2mrKeyPath.LEAF_VERSION});
        if(!Arrays.equals(leaf.value, expectedLeafValue)) {
            throw new IllegalArgumentException("input " + inputIndex + " does not carry the exact Qparrow leaf");
        }

        MapEntry root = inputMap.singleType(PSBT_IN_P2MR_MERKLE_ROOT, true, inputIndex);
        if(root.key.length != 1 || !Arrays.equals(root.value, address.merkleRoot())) {
            throw new IllegalArgumentException("input " + inputIndex + " has a mismatched P2MR merkle root");
        }
    }

    private static long validateIntent(List<TxOut> spentOutputs, List<TxOut> outputs, BtqSpendIntent intent) {
        Map<OutputKey, Integer> required = new HashMap<>();
        for(BtqSpendIntent.Payment payment : intent.payments()) {
            required.merge(new OutputKey(payment.amountSats(), payment.scriptPubKey()), 1, Integer::sum);
        }
        byte[] changeScript = intent.changeScriptPubKey();
        int changeCount = 0;
        long inputTotal = 0;
        long outputTotal = 0;
        try {
            for(TxOut input : spentOutputs) inputTotal = Math.addExact(inputTotal, input.value);
            for(TxOut output : outputs) {
                BtqSpendIntent.requireP2mr(output.scriptPubKey, "transaction output");
                outputTotal = Math.addExact(outputTotal, output.value);
                OutputKey key = new OutputKey(output.value, output.scriptPubKey);
                Integer count = required.get(key);
                if(count != null && count > 0) {
                    if(count == 1) required.remove(key); else required.put(key, count - 1);
                } else if(changeScript != null && Arrays.equals(changeScript, output.scriptPubKey)) {
                    if(output.value <= 0) {
                        throw new IllegalArgumentException("change output must be positive");
                    }
                    if(++changeCount > 1) {
                        throw new IllegalArgumentException("transaction contains more than one change output");
                    }
                } else {
                    throw new IllegalArgumentException("transaction contains an output that was not approved");
                }
            }
        } catch(ArithmeticException e) {
            throw new IllegalArgumentException("transaction amount overflow", e);
        }
        if(!required.isEmpty()) {
            throw new IllegalArgumentException("transaction is missing an approved payment");
        }
        long fee;
        try {
            fee = Math.subtractExact(inputTotal, outputTotal);
        } catch(ArithmeticException e) {
            throw new IllegalArgumentException("transaction fee overflow", e);
        }
        if(fee < 0 || fee > intent.maximumFeeSats()) {
            throw new IllegalArgumentException("transaction fee exceeds the approved ceiling");
        }
        return fee;
    }

    private static byte[] signatureHash(Transaction tx, List<TxOut> spentOutputs, int inputIndex, byte[] leafScript) {
        ByteArrayOutputStream message = new ByteArrayOutputStream(212);
        message.write(0); // epoch
        message.write(BtqMldsa44.SIGHASH_ALL);
        writeInt32(message, tx.version);
        writeUint32(message, tx.lockTime);

        ByteArrayOutputStream prevouts = new ByteArrayOutputStream();
        ByteArrayOutputStream amounts = new ByteArrayOutputStream();
        ByteArrayOutputStream scripts = new ByteArrayOutputStream();
        ByteArrayOutputStream sequences = new ByteArrayOutputStream();
        for(int i = 0; i < tx.inputs.size(); i++) {
            TxIn input = tx.inputs.get(i);
            prevouts.writeBytes(input.txid);
            writeUint32(prevouts, input.vout);
            writeInt64(amounts, spentOutputs.get(i).value);
            writeCompactSize(scripts, spentOutputs.get(i).scriptPubKey.length);
            scripts.writeBytes(spentOutputs.get(i).scriptPubKey);
            writeUint32(sequences, input.sequence);
        }
        message.writeBytes(sha256(prevouts.toByteArray()));
        message.writeBytes(sha256(amounts.toByteArray()));
        message.writeBytes(sha256(scripts.toByteArray()));
        message.writeBytes(sha256(sequences.toByteArray()));

        ByteArrayOutputStream serializedOutputs = new ByteArrayOutputStream();
        for(TxOut output : tx.outputs) writeTxOut(serializedOutputs, output);
        message.writeBytes(sha256(serializedOutputs.toByteArray()));
        message.write(2); // ext_flag=1 (script path), no annex
        writeUint32(message, inputIndex);
        message.writeBytes(BtqP2mrKeyPath.tapLeafHash(leafScript));
        message.write(0); // key version
        writeUint32(message, 0xffffffffL); // no OP_CODESEPARATOR

        MessageDigest digest = sha256Digest();
        digest.update(TAP_SIGHASH_TAG);
        digest.update(TAP_SIGHASH_TAG);
        return digest.digest(message.toByteArray());
    }

    private static Psbt parsePsbt(byte[] bytes) {
        Reader reader = new Reader(bytes);
        if(!Arrays.equals(reader.readBytes(MAGIC.length), MAGIC)) {
            throw new IllegalArgumentException("not a PSBT");
        }
        MapData global = reader.readMap("global");
        MapEntry unsigned = global.singleType(PSBT_GLOBAL_UNSIGNED_TX, true, -1);
        if(unsigned.key.length != 1) {
            throw new IllegalArgumentException("malformed global unsigned transaction key");
        }
        MapEntry version = global.singleType(PSBT_GLOBAL_VERSION, false, -1);
        if(version != null && (version.key.length != 1 || version.value.length != 4 || readUint32(version.value, 0) != 0)) {
            throw new IllegalArgumentException("only PSBT version 0 is supported");
        }
        Transaction tx = parseUnsignedTransaction(unsigned.value);
        List<MapData> inputs = new ArrayList<>(tx.inputs.size());
        List<MapData> outputs = new ArrayList<>(tx.outputs.size());
        for(int i = 0; i < tx.inputs.size(); i++) inputs.add(reader.readMap("input " + i));
        for(int i = 0; i < tx.outputs.size(); i++) outputs.add(reader.readMap("output " + i));
        if(!reader.atEnd()) {
            throw new IllegalArgumentException("trailing bytes after PSBT maps");
        }
        return new Psbt(global, unsigned.value.clone(), inputs, outputs);
    }

    private static Transaction parseUnsignedTransaction(byte[] bytes) {
        Reader reader = new Reader(bytes);
        int version = reader.readInt32();
        if(version != 2) {
            throw new IllegalArgumentException("Qparrow custody signs only version 2 transactions");
        }
        long inputCount = reader.readCompactSize();
        if(inputCount < 1 || inputCount > MAX_SIGNING_INPUTS) {
            throw new IllegalArgumentException("unsupported unsigned transaction input count");
        }
        List<TxIn> inputs = new ArrayList<>((int)inputCount);
        for(int i = 0; i < inputCount; i++) {
            byte[] txid = reader.readBytes(32);
            long vout = reader.readUint32();
            byte[] scriptSig = reader.readVarBytes(10_000);
            if(scriptSig.length != 0) {
                throw new IllegalArgumentException("unsigned transaction input has a scriptSig");
            }
            inputs.add(new TxIn(txid, vout, reader.readUint32()));
        }
        long outputCount = reader.readCompactSize();
        if(outputCount < 1 || outputCount > MAX_OUTPUTS) {
            throw new IllegalArgumentException("unsupported unsigned transaction output count");
        }
        List<TxOut> outputs = new ArrayList<>((int)outputCount);
        for(int i = 0; i < outputCount; i++) outputs.add(reader.readTxOut("transaction output " + i));
        long lockTime = reader.readUint32();
        if(!reader.atEnd()) {
            throw new IllegalArgumentException("trailing bytes in unsigned transaction");
        }
        return new Transaction(version, inputs, outputs, lockTime);
    }

    private static TxOut parseTxOut(byte[] bytes, String name) {
        Reader reader = new Reader(bytes);
        TxOut output = reader.readTxOut(name);
        if(!reader.atEnd()) throw new IllegalArgumentException("trailing bytes in " + name);
        return output;
    }

    private static byte[] serializePsbt(Psbt psbt) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(MAGIC);
        writeMap(output, psbt.globalMap);
        for(MapData map : psbt.inputMaps) writeMap(output, map);
        for(MapData map : psbt.outputMaps) writeMap(output, map);
        return output.toByteArray();
    }

    /**
     * Compute a txid from the finalized wire transaction without trusting the node's decoder.
     * Qparrow only signs version-2 P2MR inputs, so every finalized input must carry a witness.
     */
    static String finalizedTransactionId(String transactionHex) {
        if(transactionHex == null || transactionHex.isBlank() || (transactionHex.length() & 1) != 0
                || transactionHex.length() > MAX_FINALIZED_TRANSACTION_BYTES * 2) {
            throw new IllegalArgumentException("invalid finalized transaction hex");
        }

        final byte[] bytes;
        try {
            bytes = HEX.parseHex(transactionHex);
        } catch(IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid finalized transaction hex", e);
        }

        Reader reader = new Reader(bytes);
        int version = reader.readInt32();
        if(version != 2 || reader.readUnsignedByte() != 0 || reader.readUnsignedByte() != 1) {
            throw new IllegalArgumentException("finalized Qparrow transaction must use version 2 witness serialization");
        }

        long inputCount = reader.readCompactSize();
        if(inputCount < 1 || inputCount > MAX_SIGNING_INPUTS) {
            throw new IllegalArgumentException("unsupported finalized transaction input count");
        }
        List<TxIn> inputs = new ArrayList<>((int)inputCount);
        for(int i = 0; i < inputCount; i++) {
            byte[] txid = reader.readBytes(32);
            long vout = reader.readUint32();
            if(reader.readVarBytes(10_000).length != 0) {
                throw new IllegalArgumentException("finalized P2MR input has a scriptSig");
            }
            inputs.add(new TxIn(txid, vout, reader.readUint32()));
        }

        long outputCount = reader.readCompactSize();
        if(outputCount < 1 || outputCount > MAX_OUTPUTS) {
            throw new IllegalArgumentException("unsupported finalized transaction output count");
        }
        List<TxOut> outputs = new ArrayList<>((int)outputCount);
        for(int i = 0; i < outputCount; i++) outputs.add(reader.readTxOut("finalized transaction output " + i));

        for(int inputIndex = 0; inputIndex < inputCount; inputIndex++) {
            long witnessItems = reader.readCompactSize();
            if(witnessItems < 1 || witnessItems > 16) {
                throw new IllegalArgumentException("invalid finalized P2MR witness item count");
            }
            for(int item = 0; item < witnessItems; item++) {
                reader.readVarBytes(MAX_FINALIZED_TRANSACTION_BYTES);
            }
        }

        long lockTime = reader.readUint32();
        if(!reader.atEnd()) {
            throw new IllegalArgumentException("trailing bytes in finalized transaction");
        }

        ByteArrayOutputStream nonWitness = new ByteArrayOutputStream(bytes.length);
        writeInt32(nonWitness, version);
        writeCompactSize(nonWitness, inputs.size());
        for(TxIn input : inputs) {
            nonWitness.writeBytes(input.txid);
            writeUint32(nonWitness, input.vout);
            nonWitness.write(0);
            writeUint32(nonWitness, input.sequence);
        }
        writeCompactSize(nonWitness, outputs.size());
        for(TxOut output : outputs) writeTxOut(nonWitness, output);
        writeUint32(nonWitness, lockTime);
        return wireTxidHex(sha256(sha256(nonWitness.toByteArray())));
    }

    private static void writeMap(ByteArrayOutputStream output, MapData map) {
        for(MapEntry entry : map.entries) {
            writeCompactSize(output, entry.key.length);
            output.writeBytes(entry.key);
            writeCompactSize(output, entry.value.length);
            output.writeBytes(entry.value);
        }
        output.write(0);
    }

    private static void writeTxOut(ByteArrayOutputStream output, TxOut txOut) {
        writeInt64(output, txOut.value);
        writeCompactSize(output, txOut.scriptPubKey.length);
        output.writeBytes(txOut.scriptPubKey);
    }

    private static byte[] concat(byte[]... values) {
        int length = 0;
        for(byte[] value : values) length = Math.addExact(length, value.length);
        byte[] result = new byte[length];
        int offset = 0;
        for(byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }

    private static String wireTxidHex(byte[] wireTxid) {
        byte[] display = wireTxid.clone();
        for(int left = 0, right = display.length - 1; left < right; left++, right--) {
            byte value = display[left];
            display[left] = display[right];
            display[right] = value;
        }
        return HexFormat.of().formatHex(display);
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

    private static void writeCompactSize(ByteArrayOutputStream output, long value) {
        if(value < 0) throw new IllegalArgumentException("negative compact size");
        if(value < 253) {
            output.write((int)value);
        } else if(value <= 0xffffL) {
            output.write(253);
            writeLittleEndian(output, value, 2);
        } else if(value <= 0xffffffffL) {
            output.write(254);
            writeLittleEndian(output, value, 4);
        } else {
            output.write(255);
            writeLittleEndian(output, value, 8);
        }
    }

    private static void writeInt32(ByteArrayOutputStream output, int value) {
        writeLittleEndian(output, value & 0xffffffffL, 4);
    }

    private static void writeUint32(ByteArrayOutputStream output, long value) {
        if(value < 0 || value > 0xffffffffL) throw new IllegalArgumentException("uint32 out of range");
        writeLittleEndian(output, value, 4);
    }

    private static void writeInt64(ByteArrayOutputStream output, long value) {
        writeLittleEndian(output, value, 8);
    }

    private static void writeLittleEndian(ByteArrayOutputStream output, long value, int bytes) {
        for(int i = 0; i < bytes; i++) output.write((int)(value >>> (8 * i)) & 0xff);
    }

    private static long readUint32(byte[] bytes, int offset) {
        if(offset < 0 || offset + 4 > bytes.length) throw new IllegalArgumentException("truncated uint32");
        return (bytes[offset] & 0xffL) | ((bytes[offset + 1] & 0xffL) << 8)
                | ((bytes[offset + 2] & 0xffL) << 16) | ((bytes[offset + 3] & 0xffL) << 24);
    }

    private record Psbt(MapData globalMap, byte[] unsignedTransaction, List<MapData> inputMaps,
                        List<MapData> outputMaps) {
    }

    private record Processed(String base64, long feeSats, List<String> sighashes, String expectedTxid) {
    }

    private static final class MapData {
        private final List<MapEntry> entries;

        private MapData(List<MapEntry> entries) {
            this.entries = entries;
        }

        private boolean hasType(int type) {
            return entries.stream().anyMatch(entry -> (entry.key[0] & 0xff) == type);
        }

        private MapEntry singleType(int type, boolean required, int inputIndex) {
            MapEntry found = null;
            for(MapEntry entry : entries) {
                if((entry.key[0] & 0xff) == type) {
                    if(found != null) {
                        throw new IllegalArgumentException(location(inputIndex) + " has more than one field of type 0x" + Integer.toHexString(type));
                    }
                    found = entry;
                }
            }
            if(required && found == null) {
                throw new IllegalArgumentException(location(inputIndex) + " is missing field type 0x" + Integer.toHexString(type));
            }
            return found;
        }

        private void add(MapEntry entry) {
            ByteKey key = new ByteKey(entry.key);
            if(entries.stream().anyMatch(existing -> new ByteKey(existing.key).equals(key))) {
                throw new IllegalArgumentException("duplicate PSBT key");
            }
            entries.add(entry);
        }

        private static String location(int inputIndex) {
            return inputIndex < 0 ? "global map" : "input " + inputIndex;
        }
    }

    private record MapEntry(byte[] key, byte[] value) {
        private MapEntry {
            if(key == null || key.length == 0) throw new IllegalArgumentException("empty PSBT key");
            key = key.clone();
            value = Objects.requireNonNull(value, "PSBT value").clone();
        }
    }

    private record Transaction(int version, List<TxIn> inputs, List<TxOut> outputs, long lockTime) {
    }

    private record TxIn(byte[] txid, long vout, long sequence) {
        private TxIn {
            txid = txid.clone();
        }
    }

    private record TxOut(long value, byte[] scriptPubKey) {
        private TxOut {
            if(value < 0 || value > MAX_MONEY_SATS) {
                throw new IllegalArgumentException("transaction output is outside the monetary range");
            }
            scriptPubKey = scriptPubKey.clone();
        }
    }

    private record SigningInput(byte[] keySeed, BtqP2mrKeyPath.Address address) {
    }

    private static final class OutputKey {
        private final long amount;
        private final byte[] script;

        private OutputKey(long amount, byte[] script) {
            this.amount = amount;
            this.script = script.clone();
        }

        @Override
        public boolean equals(Object object) {
            return object instanceof OutputKey other && amount == other.amount && Arrays.equals(script, other.script);
        }

        @Override
        public int hashCode() {
            return 31 * Long.hashCode(amount) + Arrays.hashCode(script);
        }
    }

    private static final class ByteKey {
        private final byte[] bytes;

        private ByteKey(byte[] bytes) {
            this.bytes = bytes;
        }

        @Override
        public boolean equals(Object object) {
            return object instanceof ByteKey other && Arrays.equals(bytes, other.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }
    }

    private static final class Reader {
        private final byte[] bytes;
        private int offset;

        private Reader(byte[] bytes) {
            this.bytes = Objects.requireNonNull(bytes, "bytes");
        }

        private boolean atEnd() {
            return offset == bytes.length;
        }

        private byte[] readBytes(int length) {
            if(length < 0 || offset + length < offset || offset + length > bytes.length) {
                throw new IllegalArgumentException("truncated data");
            }
            byte[] result = Arrays.copyOfRange(bytes, offset, offset + length);
            offset += length;
            return result;
        }

        private long readCompactSize() {
            int first = readUnsignedByte();
            if(first < 253) return first;
            int count = first == 253 ? 2 : first == 254 ? 4 : 8;
            long value = 0;
            byte[] encoded = readBytes(count);
            for(int i = 0; i < count; i++) value |= (encoded[i] & 0xffL) << (8 * i);
            if(value < 0 || (first == 253 && value < 253) || (first == 254 && value <= 0xffffL)
                    || (first == 255 && value <= 0xffffffffL)) {
                throw new IllegalArgumentException("non-canonical compact size");
            }
            return value;
        }

        private int readUnsignedByte() {
            return readBytes(1)[0] & 0xff;
        }

        private byte[] readVarBytes(int maximum) {
            long length = readCompactSize();
            if(length > maximum) throw new IllegalArgumentException("variable byte field exceeds limit");
            return readBytes((int)length);
        }

        private int readInt32() {
            return (int)readUint32();
        }

        private long readUint32() {
            byte[] value = readBytes(4);
            return BtqPsbtSigner.readUint32(value, 0);
        }

        private long readInt64() {
            byte[] value = readBytes(8);
            long result = 0;
            for(int i = 0; i < 8; i++) result |= (value[i] & 0xffL) << (8 * i);
            return result;
        }

        private TxOut readTxOut(String name) {
            long value = readInt64();
            if(value < 0) throw new IllegalArgumentException(name + " has a negative amount");
            return new TxOut(value, readVarBytes(10_000));
        }

        private MapData readMap(String name) {
            List<MapEntry> entries = new ArrayList<>();
            Set<ByteKey> keys = new HashSet<>();
            while(true) {
                long keyLength = readCompactSize();
                if(keyLength == 0) break;
                if(keyLength > 4096) throw new IllegalArgumentException(name + " key exceeds limit");
                byte[] key = readBytes((int)keyLength);
                ByteKey byteKey = new ByteKey(key);
                if(!keys.add(byteKey)) throw new IllegalArgumentException(name + " contains a duplicate key");
                long valueLength = readCompactSize();
                if(valueLength > 2 * 1024 * 1024) throw new IllegalArgumentException(name + " value exceeds limit");
                entries.add(new MapEntry(key, readBytes((int)valueLength)));
            }
            return new MapData(entries);
        }
    }
}
