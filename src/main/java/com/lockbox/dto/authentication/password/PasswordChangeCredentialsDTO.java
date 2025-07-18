package com.lockbox.dto.authentication.password;

public class PasswordChangeCredentialsDTO {
    private String clientProofM1;
    private String newSalt;
    private String newDerivedKey;
    private String newDerivedUsername;
    private String newVerifier;

    public String getClientProofM1() {
        return clientProofM1;
    }

    public void setClientProofM1(String clientProofM1) {
        this.clientProofM1 = clientProofM1;
    }

    public String getNewSalt() {
        return newSalt;
    }

    public void setNewSalt(String newSalt) {
        this.newSalt = newSalt;
    }

    public String getNewDerivedKey() {
        return newDerivedKey;
    }

    public void setNewDerivedKey(String newDerivedKey) {
        this.newDerivedKey = newDerivedKey;
    }

    public String getNewDerivedUsername() {
        return newDerivedUsername;
    }

    public void setNewDerivedUsername(String newDerivedUsername) {
        this.newDerivedUsername = newDerivedUsername;
    }

    public String getNewVerifier() {
        return newVerifier;
    }

    public void setNewVerifier(String newVerifier) {
        this.newVerifier = newVerifier;
    }
}