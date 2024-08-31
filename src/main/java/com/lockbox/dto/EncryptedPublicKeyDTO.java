package com.lockbox.dto;

public class EncryptedPublicKeyDTO {
    private String clientPublicKey;

    private String ivClientPublicKey;

    private String hmacClientPublicKey;

    public String getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(String clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public String getIvClientPublicKey() {
        return ivClientPublicKey;
    }

    public void setIvClientPublicKey(String ivClientPublicKey) {
        this.ivClientPublicKey = ivClientPublicKey;
    }

    public String getHmacClientPublicKey() {
        return hmacClientPublicKey;
    }

    public void setHmacClientPublicKey(String hmacClientPublicKey) {
        this.hmacClientPublicKey = hmacClientPublicKey;
    }
}
