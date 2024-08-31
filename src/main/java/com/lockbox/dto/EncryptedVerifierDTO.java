package com.lockbox.dto;

public class EncryptedVerifierDTO {
    private String verifier;

    private String ivVerifier;

    private String hmacVerifier;

    public String getVerifier() {
        return verifier;
    }

    public void setVerifier(String verifier) {
        this.verifier = verifier;
    }

    public String getIvVerifier() {
        return ivVerifier;
    }

    public void setIvVerifier(String ivVerifier) {
        this.ivVerifier = ivVerifier;
    }

    public String getHmacVerifier() {
        return hmacVerifier;
    }

    public void setHmacVerifier(String hmacVerifier) {
        this.hmacVerifier = hmacVerifier;
    }
}
