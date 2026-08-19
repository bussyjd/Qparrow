// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import com.sparrowwallet.sparrow.btq.BtqNetwork;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

import java.util.Arrays;
import java.util.Objects;

/**
 * Escape hatch: export one derived ML-DSA-44 secret key as a BTQ Core Dilithium
 * WIF so the funds behind a single P2MR address can be recovered by the
 * reference wallet ({@code importdilithiumkey}) if Qparrow is ever unavailable.
 *
 * <p>The WIF is exactly what BTQ Core's {@code DecodeDilithiumSecret} expects:
 * {@code Base58Check( secretKeyPrefix ‖ sk(2560) ‖ pk(1312) )}
 * (src/key_io.cpp:365-386, prefix {@code base58Prefixes[SECRET_KEY]} =
 * 235 on mainnet, 239 on test/signet/regtest — src/kernel/chainparams.cpp).
 * Importing it yields the byte-identical single-leaf P2MR destination this
 * wallet derived, verified end to end in {@code BtqCoreRegtestIntegrationTest}.</p>
 *
 * <p>This is a recovery-only path and is never used while signing. Anyone who
 * obtains an exported WIF controls that one address's funds, so callers must
 * treat the returned string as raw secret key material.</p>
 */
public final class BtqKeyExport {
    /** Length of a decoded BTQ Dilithium WIF payload: 1-byte prefix + sk + pk. */
    public static final int WIF_PAYLOAD_BYTES =
            1 + BtqMldsa44.SECRET_KEY_BYTES + BtqMldsa44.PUBLIC_KEY_BYTES;

    private BtqKeyExport() {
    }

    /**
     * Export the ML-DSA-44 secret key for one derivation as a BTQ Core Dilithium WIF.
     *
     * @param masterSecret the 32-byte vault master secret (not retained or mutated)
     * @param network      the BTQ network the key belongs to (fixes the WIF prefix)
     * @param chain        receive or change
     * @param index        the derivation index
     * @return a Base58Check Dilithium WIF importable via {@code importdilithiumkey}
     */
    public static String exportDilithiumWif(byte[] masterSecret, BtqNetwork network,
                                            BtqCustodySpec.Chain chain, int index) {
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(chain, "chain");
        byte[] seed = BtqCustodySpec.deriveKeySeed(masterSecret, network, chain, index);
        byte[] secretKey = null;
        byte[] publicKey = null;
        byte[] payload = null;
        try {
            MLDSAPrivateKeyParameters keyPair =
                    new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, seed);
            secretKey = keyPair.getPrivateKey();
            publicKey = keyPair.getPublicKey();
            BtqCustodySpec.requireLength(secretKey, BtqMldsa44.SECRET_KEY_BYTES, "ML-DSA secret key");
            BtqCustodySpec.requireLength(publicKey, BtqMldsa44.PUBLIC_KEY_BYTES, "ML-DSA public key");

            payload = new byte[WIF_PAYLOAD_BYTES];
            payload[0] = secretKeyPrefix(network);
            System.arraycopy(secretKey, 0, payload, 1, secretKey.length);
            System.arraycopy(publicKey, 0, payload, 1 + secretKey.length, publicKey.length);
            return BtqBase58Check.encode(payload);
        } finally {
            if(seed != null) Arrays.fill(seed, (byte)0);
            if(secretKey != null) Arrays.fill(secretKey, (byte)0);
            if(payload != null) Arrays.fill(payload, (byte)0);
            // publicKey is not secret; leave it.
        }
    }

    /** BTQ Core {@code base58Prefixes[SECRET_KEY]}: 235 on mainnet, 239 elsewhere. */
    static byte secretKeyPrefix(BtqNetwork network) {
        return switch(network) {
            case MAINNET -> (byte)235;
            case TESTNET, SIGNET, REGTEST -> (byte)239;
        };
    }
}
