package com.lockbox.dto;

public class EncryptedSessionTokenDTO {
    private String sessionToken;
    
    private String ivSessionToken;
    
    private String hmacSessionToken;

    public String getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
    }

    public String getIvSessionToken() {
        return ivSessionToken;
    }

    public void setIvSessionToken(String ivSessionToken) {
        this.ivSessionToken = ivSessionToken;
    }

    public String getHmacSessionToken() {
        return hmacSessionToken;
    }

    public void setHmacSessionToken(String hmacSessionToken) {
        this.hmacSessionToken = hmacSessionToken;
    }
}
