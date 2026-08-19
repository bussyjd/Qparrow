// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BtqP2mrAddressCodecTest {
    @Test
    void encodesCanonicalWitnessV2Bech32mForEveryBtqNetwork() {
        String root = "11".repeat(32);

        assertEquals("qbtc1z", BtqP2mrAddressCodec.encode(BtqNetwork.MAINNET, root).substring(0, 6));
        assertEquals("tbtq1z", BtqP2mrAddressCodec.encode(BtqNetwork.TESTNET, root).substring(0, 6));
        assertEquals("qtb1z", BtqP2mrAddressCodec.encode(BtqNetwork.SIGNET, root).substring(0, 5));
        assertEquals("qcrt1z", BtqP2mrAddressCodec.encode(BtqNetwork.REGTEST, root).substring(0, 6));
        assertNotEquals(BtqP2mrAddressCodec.encode(BtqNetwork.MAINNET, root),
                BtqP2mrAddressCodec.encode(BtqNetwork.REGTEST, root));
        for(BtqNetwork network : BtqNetwork.values()) {
            String address = BtqP2mrAddressCodec.encode(network, root);
            assertTrue(BtqP2mrAddressCodec.isCanonicalAddress(network, address));
            assertTrue(BtqP2mrAddressCodec.isCanonicalAddress(network, address.toUpperCase()));
            assertArrayEquals(java.util.HexFormat.of().parseHex("5220" + root),
                    BtqP2mrAddressCodec.scriptPubKey(network, address));
        }
    }

    @Test
    void rejectsWrongLengthAndNonHexRoots() {
        assertThrows(IllegalArgumentException.class, () -> BtqP2mrAddressCodec.encode(BtqNetwork.REGTEST, "11"));
        assertThrows(IllegalArgumentException.class, () -> BtqP2mrAddressCodec.encode(BtqNetwork.REGTEST, "zz".repeat(32)));
    }

    @Test
    void rejectsWrongNetworkMixedCaseAndCorruptedDestinations() {
        String address = BtqP2mrAddressCodec.encode(BtqNetwork.REGTEST, "22".repeat(32));

        assertFalse(BtqP2mrAddressCodec.isCanonicalAddress(BtqNetwork.MAINNET, address));
        assertFalse(BtqP2mrAddressCodec.isCanonicalAddress(BtqNetwork.REGTEST,
                address.substring(0, 2).toUpperCase() + address.substring(2)));
        char replacement = address.charAt(address.length() - 1) == 'q' ? 'p' : 'q';
        assertFalse(BtqP2mrAddressCodec.isCanonicalAddress(BtqNetwork.REGTEST,
                address.substring(0, address.length() - 1) + replacement));
        assertFalse(BtqP2mrAddressCodec.isCanonicalAddress(BtqNetwork.REGTEST, address + "q"));
        assertFalse(BtqP2mrAddressCodec.isCanonicalAddress(BtqNetwork.REGTEST, "qcrt1q" + address.substring(6)));
    }
}
