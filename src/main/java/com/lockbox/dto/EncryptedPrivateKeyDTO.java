package com.lockbox.dto;

public class EncryptedPrivateKeyDTO {
    private String clientPrivateKey;

    private String ivClientPrivateKey;

    private String hmacClientPrivateKey;

    public String getClientPrivateKey() {
        return clientPrivateKey;
    }

    public void setClientPrivateKey(String clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public String getIvClientPrivateKey() {
        return ivClientPrivateKey;
    }

    public void setIvClientPrivateKey(String ivClientPrivateKey) {
        this.ivClientPrivateKey = ivClientPrivateKey;
    }

    public String getHmacClientPrivateKey() {
        return hmacClientPrivateKey;
    }

    public void setHmacClientPrivateKey(String hmacClientPrivateKey) {
        this.hmacClientPrivateKey = hmacClientPrivateKey;
    }
}
