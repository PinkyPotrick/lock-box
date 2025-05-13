package com.lockbox.dto.authentication.password;

import java.math.BigInteger;

public class PasswordChangeInitDTO {
    private String derivedUsername;
    private String derivedKey;
    private BigInteger clientPublicValueA;

    public String getDerivedUsername() {
        return derivedUsername;
    }

    public void setDerivedUsername(String derivedUsername) {
        this.derivedUsername = derivedUsername;
    }

    public String getDerivedKey() {
        return derivedKey;
    }

    public void setDerivedKey(String derivedKey) {
        this.derivedKey = derivedKey;
    }

    public BigInteger getClientPublicValueA() {
        return clientPublicValueA;
    }

    public void setClientPublicValueA(BigInteger clientPublicValueA) {
        this.clientPublicValueA = clientPublicValueA;
    }
}