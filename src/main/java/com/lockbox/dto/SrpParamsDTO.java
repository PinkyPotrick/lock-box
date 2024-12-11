package com.lockbox.dto;

import java.math.BigInteger;

/**
 * The decrypted SRP parameters handled on backend.
 */
public class SrpParamsDTO {
    private String derivedUsername;

    private String clientPublicKey;

    private BigInteger clientPublicValueA;

    public String getDerivedUsername() {
        return derivedUsername;
    }

    public void setDerivedUsername(String derivedUsername) {
        this.derivedUsername = derivedUsername;
    }

    public String getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(String clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public BigInteger getClientPublicValueA() {
        return clientPublicValueA;
    }

    public void setClientPublicValueA(BigInteger clientPublicValueA) {
        this.clientPublicValueA = clientPublicValueA;
    }
}
