// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Minimal BIP350 encoder used to independently bind a P2MR address to its 32-byte merkle root. */
public final class BtqP2mrAddressCodec {
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final int BECH32M_CONSTANT = 0x2bc830a3;

    private BtqP2mrAddressCodec() {}

    public static String encode(BtqNetwork network, String merkleRootHex) {
        if(merkleRootHex == null || merkleRootHex.length() != 64) {
            throw new IllegalArgumentException("P2MR merkle root must be exactly 32 bytes");
        }
        byte[] program = new byte[32];
        for(int i = 0; i < program.length; i++) {
            int high = Character.digit(merkleRootHex.charAt(i * 2), 16);
            int low = Character.digit(merkleRootHex.charAt(i * 2 + 1), 16);
            if(high < 0 || low < 0) {
                throw new IllegalArgumentException("P2MR merkle root must be hexadecimal");
            }
            program[i] = (byte)((high << 4) | low);
        }

        List<Integer> data = new ArrayList<>();
        data.add(2); // witness version 2 / P2MR
        data.addAll(convertBits(program, 8, 5));
        int[] checksum = checksum(network.bech32Hrp(), data);
        StringBuilder address = new StringBuilder(network.bech32Hrp()).append('1');
        for(int value : data) {
            address.append(CHARSET.charAt(value));
        }
        for(int value : checksum) {
            address.append(CHARSET.charAt(value));
        }
        return address.toString().toLowerCase(Locale.ROOT);
    }

    /** Validate a same-network witness-v2, 32-byte Bech32m destination without trusting the node. */
    public static boolean isCanonicalAddress(BtqNetwork network, String address) {
        if(network == null || address == null || address.length() > 90 || address.length() < 8) {
            return false;
        }
        boolean hasLower = !address.equals(address.toUpperCase(Locale.ROOT));
        boolean hasUpper = !address.equals(address.toLowerCase(Locale.ROOT));
        if(hasLower && hasUpper) {
            return false;
        }

        String normalized = address.toLowerCase(Locale.ROOT);
        int separator = normalized.lastIndexOf('1');
        if(separator <= 0 || !network.bech32Hrp().equals(normalized.substring(0, separator))) {
            return false;
        }

        String encoded = normalized.substring(separator + 1);
        if(encoded.length() != 59) { // version + 52 program groups + 6 checksum groups
            return false;
        }
        byte[] values = new byte[encoded.length()];
        for(int i = 0; i < encoded.length(); i++) {
            int value = CHARSET.indexOf(encoded.charAt(i));
            if(value < 0) {
                return false;
            }
            values[i] = (byte)value;
        }
        if(values[0] != 2 || polymod(checksumInput(network.bech32Hrp(), values)) != BECH32M_CONSTANT) {
            return false;
        }

        byte[] program = convertBitsWithoutPadding(values, 1, values.length - 6, 5, 8);
        if(program == null || program.length != 32) {
            return false;
        }
        return encode(network, toHex(program)).equals(normalized);
    }

    /** Decode a canonical same-network P2MR address to OP_2 PUSH32 scriptPubKey. */
    public static byte[] scriptPubKey(BtqNetwork network, String address) {
        if(!isCanonicalAddress(network, address)) {
            throw new IllegalArgumentException("address is not canonical same-network P2MR");
        }
        String normalized = address.toLowerCase(Locale.ROOT);
        int separator = normalized.lastIndexOf('1');
        String encoded = normalized.substring(separator + 1);
        byte[] values = new byte[encoded.length()];
        for(int i = 0; i < encoded.length(); i++) values[i] = (byte)CHARSET.indexOf(encoded.charAt(i));
        byte[] program = convertBitsWithoutPadding(values, 1, values.length - 6, 5, 8);
        if(program == null || program.length != 32) {
            throw new IllegalArgumentException("address has an invalid P2MR witness program");
        }
        byte[] script = new byte[34];
        script[0] = 0x52;
        script[1] = 0x20;
        System.arraycopy(program, 0, script, 2, program.length);
        return script;
    }

    private static List<Integer> convertBits(byte[] input, int fromBits, int toBits) {
        int accumulator = 0;
        int bits = 0;
        int maxValue = (1 << toBits) - 1;
        int maxAccumulator = (1 << (fromBits + toBits - 1)) - 1;
        List<Integer> output = new ArrayList<>();
        for(byte inputByte : input) {
            int value = inputByte & 0xff;
            accumulator = ((accumulator << fromBits) | value) & maxAccumulator;
            bits += fromBits;
            while(bits >= toBits) {
                bits -= toBits;
                output.add((accumulator >> bits) & maxValue);
            }
        }
        if(bits > 0) {
            output.add((accumulator << (toBits - bits)) & maxValue);
        }
        return output;
    }

    private static byte[] convertBitsWithoutPadding(byte[] input, int offset, int limit, int fromBits, int toBits) {
        int accumulator = 0;
        int bits = 0;
        int maxValue = (1 << toBits) - 1;
        int maxAccumulator = (1 << (fromBits + toBits - 1)) - 1;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for(int i = offset; i < limit; i++) {
            int value = input[i] & 0xff;
            if((value >>> fromBits) != 0) {
                return null;
            }
            accumulator = ((accumulator << fromBits) | value) & maxAccumulator;
            bits += fromBits;
            while(bits >= toBits) {
                bits -= toBits;
                output.write((accumulator >>> bits) & maxValue);
            }
        }
        if(bits >= fromBits || ((accumulator << (toBits - bits)) & maxValue) != 0) {
            return null;
        }
        return output.toByteArray();
    }

    private static int[] checksum(String hrp, List<Integer> data) {
        byte[] payload = new byte[data.size() + 6];
        for(int i = 0; i < data.size(); i++) payload[i] = data.get(i).byteValue();

        int polymod = polymod(checksumInput(hrp, payload)) ^ BECH32M_CONSTANT;
        int[] checksum = new int[6];
        for(int i = 0; i < checksum.length; i++) {
            checksum[i] = (polymod >> (5 * (5 - i))) & 31;
        }
        return checksum;
    }

    private static byte[] checksumInput(String hrp, byte[] data) {
        ByteArrayOutputStream values = new ByteArrayOutputStream();
        for(int i = 0; i < hrp.length(); i++) values.write(hrp.charAt(i) >> 5);
        values.write(0);
        for(int i = 0; i < hrp.length(); i++) values.write(hrp.charAt(i) & 31);
        values.writeBytes(data);
        return values.toByteArray();
    }

    private static String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for(byte value : bytes) {
            hex.append(Character.forDigit((value >>> 4) & 0xf, 16));
            hex.append(Character.forDigit(value & 0xf, 16));
        }
        return hex.toString();
    }

    private static int polymod(byte[] values) {
        int checksum = 1;
        int[] generators = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
        for(byte rawValue : values) {
            int top = checksum >>> 25;
            checksum = ((checksum & 0x1ffffff) << 5) ^ (rawValue & 0xff);
            for(int i = 0; i < generators.length; i++) {
                if(((top >>> i) & 1) != 0) checksum ^= generators[i];
            }
        }
        return checksum;
    }
}
