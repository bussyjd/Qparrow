// Copyright (c) 2026 The Qparrow developers
// Licensed under the Apache License, Version 2.0.
package com.sparrowwallet.sparrow.btq.custody;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Exact user-approved outputs and fee ceiling for one BTQ signing operation. */
public final class BtqSpendIntent {
    private final List<Payment> payments;
    private final byte[] changeScriptPubKey;
    private final long maximumFeeSats;

    public BtqSpendIntent(List<Payment> payments, byte[] changeScriptPubKey, long maximumFeeSats) {
        if(payments == null || payments.isEmpty()) {
            throw new IllegalArgumentException("at least one payment is required");
        }
        this.payments = List.copyOf(payments);
        this.changeScriptPubKey = changeScriptPubKey == null ? null : requireP2mr(changeScriptPubKey, "change script");
        if(maximumFeeSats < 0) {
            throw new IllegalArgumentException("maximum fee cannot be negative");
        }
        this.maximumFeeSats = maximumFeeSats;

        for(Payment payment : this.payments) {
            if(this.changeScriptPubKey != null && Arrays.equals(payment.scriptPubKey, this.changeScriptPubKey)) {
                throw new IllegalArgumentException("change script must be distinct from every payment script");
            }
        }
    }

    public List<Payment> payments() {
        return new ArrayList<>(payments);
    }

    public byte[] changeScriptPubKey() {
        return changeScriptPubKey == null ? null : changeScriptPubKey.clone();
    }

    public long maximumFeeSats() {
        return maximumFeeSats;
    }

    static byte[] requireP2mr(byte[] script, String name) {
        Objects.requireNonNull(script, name);
        if(script.length != 34 || script[0] != 0x52 || script[1] != 0x20) {
            throw new IllegalArgumentException(name + " must be an exact witness-v2 P2MR script");
        }
        return script.clone();
    }

    public static final class Payment {
        private final byte[] scriptPubKey;
        private final long amountSats;

        public Payment(byte[] scriptPubKey, long amountSats) {
            this.scriptPubKey = requireP2mr(scriptPubKey, "payment script");
            if(amountSats <= 0) {
                throw new IllegalArgumentException("payment amount must be positive");
            }
            this.amountSats = amountSats;
        }

        public byte[] scriptPubKey() {
            return scriptPubKey.clone();
        }

        public long amountSats() {
            return amountSats;
        }
    }
}
