// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

class BtqCustodyPrimitivesTest {
    private static final HexFormat HEX = HexFormat.of();

    @Test
    void mldsaKeygenMatchesNistAcvpAndCoreP2mrVector() {
        // NIST ACVP ML-DSA-44 keyGen tcId 1, also executed by BTQ Core's
        // dilithium_kat_tests. The P2MR values were independently produced by
        // BTQ Core getnewp2mraddress in a private-key-disabled regtest wallet.
        byte[] seed = HEX.parseHex("7194b13c95231010afd2c909992bd2003ba6f437c3886bdbe3f6b867a14ba161");
        byte[] publicKey = BtqMldsa44.publicKeyFromSeed(seed);

        assertEquals(BtqMldsa44.PUBLIC_KEY_BYTES, publicKey.length);
        assertEquals("838b88b6ac41e2c60698173e08ca173d0b0d2839205806e56a8a3d53195f3a03",
                HEX.formatHex(sha256(publicKey)));

        BtqP2mrKeyPath.Address result = BtqP2mrKeyPath.fromPublicKey(
                BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 0, publicKey);
        assertEquals("0dac4f43a7cb1af28471eb4b8e0acb42b4dd8baee8cb5b4e6c423a98f0caccb8",
                HEX.formatHex(result.merkleRoot()));
        assertEquals("52200dac4f43a7cb1af28471eb4b8e0acb42b4dd8baee8cb5b4e6c423a98f0caccb8",
                HEX.formatHex(result.scriptPubKey()));
        assertEquals("qcrt1zpkky7sa8evd09pr3ad9cuzktg26dmzawar94knnvggaf3ux2ejuqtcg4ye",
                result.address());
        assertArrayEquals(new byte[]{(byte)0xc1}, result.controlBlock());
        assertEquals(1316, result.leafScript().length);
        assertArrayEquals(new byte[]{0x4d, 0x20, 0x05}, Arrays.copyOf(result.leafScript(), 3));
        assertEquals((byte)0xbb, result.leafScript()[result.leafScript().length - 1]);
    }

    @Test
    void deterministicTransactionSignatureMatchesBtqCore() {
        byte[] seed = new byte[BtqMldsa44.SEED_BYTES];
        for(int i = 0; i < seed.length; i++) {
            seed[i] = (byte)i;
        }
        byte[] transactionHash = new byte[BtqMldsa44.TRANSACTION_HASH_BYTES];

        byte[] signature = BtqMldsa44.signTransactionHash(seed, transactionHash);
        assertEquals(BtqMldsa44.TRANSACTION_SIGNATURE_BYTES, signature.length);
        assertEquals(BtqMldsa44.SIGHASH_ALL, signature[BtqMldsa44.SIGNATURE_BYTES]);
        assertEquals("c59941604dd8eb958dd33951196d95c789e5de40b11e18a63fc476289a756410",
                HEX.formatHex(sha256(Arrays.copyOf(signature, BtqMldsa44.SIGNATURE_BYTES))));

        byte[] publicKey = BtqMldsa44.publicKeyFromSeed(seed);
        assertTrue(BtqMldsa44.verifyTransactionHash(publicKey, transactionHash, signature));

        byte[] mutated = signature.clone();
        mutated[100] ^= 1;
        assertFalse(BtqMldsa44.verifyTransactionHash(publicKey, transactionHash, mutated));
        mutated = signature.clone();
        mutated[BtqMldsa44.SIGNATURE_BYTES] = 0;
        assertFalse(BtqMldsa44.verifyTransactionHash(publicKey, transactionHash, mutated));
    }

    @Test
    void v1DerivationIsDeterministicAndDomainSeparated() {
        byte[] master = new byte[BtqCustodySpec.MASTER_SECRET_BYTES];
        for(int i = 0; i < master.length; i++) {
            master[i] = (byte)i;
        }

        byte[] receive0 = BtqCustodySpec.deriveKeySeed(master, BtqNetwork.MAINNET, BtqCustodySpec.Chain.RECEIVE, 0);
        assertEquals("03d72656440b5dfe73998e43e8b3fe2b463e57a140294e28b6b90cc115ec4b9d", HEX.formatHex(receive0));
        assertArrayEquals(receive0,
                BtqCustodySpec.deriveKeySeed(master, BtqNetwork.MAINNET, BtqCustodySpec.Chain.RECEIVE, 0));
        assertFalse(Arrays.equals(receive0,
                BtqCustodySpec.deriveKeySeed(master, BtqNetwork.MAINNET, BtqCustodySpec.Chain.CHANGE, 0)));
        assertFalse(Arrays.equals(receive0,
                BtqCustodySpec.deriveKeySeed(master, BtqNetwork.MAINNET, BtqCustodySpec.Chain.RECEIVE, 1)));
        assertFalse(Arrays.equals(receive0,
                BtqCustodySpec.deriveKeySeed(master, BtqNetwork.REGTEST, BtqCustodySpec.Chain.RECEIVE, 0)));
    }

    @Test
    void addressMaterialIsDefensivelyCopied() {
        byte[] publicKey = BtqMldsa44.publicKeyFromSeed(new byte[BtqMldsa44.SEED_BYTES]);
        BtqP2mrKeyPath.Address result = BtqP2mrKeyPath.fromPublicKey(
                BtqNetwork.MAINNET, BtqCustodySpec.Chain.RECEIVE, 0, publicKey);
        byte[] root = result.merkleRoot();
        root[0] ^= 1;
        assertNotEquals(root[0], result.merkleRoot()[0]);
    }

    @Test
    void malformedSecretAndIndicesFailClosed() {
        assertThrows(IllegalArgumentException.class,
                () -> BtqMldsa44.publicKeyFromSeed(new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> BtqCustodySpec.deriveKeySeed(new byte[32], BtqNetwork.MAINNET, BtqCustodySpec.Chain.RECEIVE, -1));
        assertThrows(IllegalArgumentException.class,
                () -> BtqP2mrKeyPath.fromPublicKey(BtqNetwork.MAINNET, BtqCustodySpec.Chain.RECEIVE, 0, new byte[33]));
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch(NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }
}
