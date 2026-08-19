// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class BtqKeyExportTest {

    @Test
    void base58CheckRoundTripsArbitraryPayloads() {
        SecureRandom random = new SecureRandom();
        for(int length : new int[]{1, 21, 33, BtqKeyExport.WIF_PAYLOAD_BYTES}) {
            byte[] payload = new byte[length];
            random.nextBytes(payload);
            String encoded = BtqBase58Check.encode(payload);
            assertArrayEquals(payload, BtqBase58Check.decode(encoded));
        }
    }

    @Test
    void base58CheckRejectsCorruptedInput() {
        byte[] payload = new byte[]{(byte)239, 1, 2, 3, 4};
        String encoded = BtqBase58Check.encode(payload);
        // Flip one character to break the checksum.
        char[] chars = encoded.toCharArray();
        chars[chars.length - 1] = chars[chars.length - 1] == 'A' ? 'B' : 'A';
        assertThrows(IllegalArgumentException.class, () -> BtqBase58Check.decode(new String(chars)));
        assertThrows(IllegalArgumentException.class, () -> BtqBase58Check.decode("not base58 0OIl"));
    }

    @Test
    void base58CheckMatchesAKnownBitcoinVector() {
        // Bitcoin mainnet P2PKH 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH decodes to
        // version 0x00 + 20-byte hash (a canonical Base58Check test vector).
        byte[] payload = HexFormat.of().parseHex("00010966776006953d5567439e5e39f86a0d273bee");
        assertEquals("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", BtqBase58Check.encode(payload));
    }

    @Test
    void exportedWifEmbedsTheDerivedPublicKeyAndDecodesCleanly() {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        new SecureRandom().nextBytes(master);
        int index = 7;
        BtqNetwork network = BtqNetwork.REGTEST;
        BtqCustodySpec.Chain chain = BtqCustodySpec.Chain.RECEIVE;

        String wif = BtqKeyExport.exportDilithiumWif(master, network, chain, index);
        byte[] decoded = BtqBase58Check.decode(wif);

        assertEquals(BtqKeyExport.WIF_PAYLOAD_BYTES, decoded.length);
        assertEquals(1 + BtqMldsa44.SECRET_KEY_BYTES + BtqMldsa44.PUBLIC_KEY_BYTES, decoded.length);
        assertEquals((byte)239, decoded[0], "regtest SECRET_KEY prefix is 239");

        // The public key embedded at offset 1 + sk must equal the wallet's derived receive key.
        byte[] embeddedPublicKey = Arrays.copyOfRange(decoded,
                1 + BtqMldsa44.SECRET_KEY_BYTES, decoded.length);
        byte[] derivedSeed = BtqCustodySpec.deriveKeySeed(master, network, chain, index);
        byte[] derivedPublicKey = BtqMldsa44.publicKeyFromSeed(derivedSeed);
        assertArrayEquals(derivedPublicKey, embeddedPublicKey,
                "WIF public key must match the wallet's derived P2MR key");

        // The embedded secret key must sign a hash that the embedded public key verifies.
        byte[] secretKey = Arrays.copyOfRange(decoded, 1, 1 + BtqMldsa44.SECRET_KEY_BYTES);
        byte[] hash = new byte[BtqMldsa44.TRANSACTION_HASH_BYTES];
        new SecureRandom().nextBytes(hash);
        byte[] rawSignature = BtqMldsa44.sign(secretKey, hash, new byte[0]);
        assertTrue(BtqMldsa44.verify(embeddedPublicKey, hash, new byte[0], rawSignature),
                "exported secret key must be the pair of the exported public key");
    }

    @Test
    void exportIsDeterministicAndNetworkScoped() {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        new SecureRandom().nextBytes(master);

        String a = BtqKeyExport.exportDilithiumWif(master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 3);
        String b = BtqKeyExport.exportDilithiumWif(master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 3);
        assertEquals(a, b, "same inputs must produce the same WIF");

        // Different network -> different derivation (and prefix) -> different WIF.
        String other = BtqKeyExport.exportDilithiumWif(master, BtqNetwork.MAINNET, BtqCustodySpec.Chain.RECEIVE, 3);
        assertNotEquals(a, other);
        assertEquals((byte)235, BtqBase58Check.decode(other)[0], "mainnet SECRET_KEY prefix is 235");

        // Different chain and index also diverge.
        assertNotEquals(a, BtqKeyExport.exportDilithiumWif(master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.CHANGE, 3));
        assertNotEquals(a, BtqKeyExport.exportDilithiumWif(master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 4));
    }

    @Test
    void secretKeyPrefixMatchesBtqCoreChainparams() {
        assertEquals((byte)235, BtqKeyExport.secretKeyPrefix(BtqNetwork.MAINNET));
        assertEquals((byte)239, BtqKeyExport.secretKeyPrefix(BtqNetwork.TESTNET));
        assertEquals((byte)239, BtqKeyExport.secretKeyPrefix(BtqNetwork.SIGNET));
        assertEquals((byte)239, BtqKeyExport.secretKeyPrefix(BtqNetwork.REGTEST));
    }
}
