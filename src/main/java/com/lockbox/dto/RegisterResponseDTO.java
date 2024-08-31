package com.lockbox.dto;

public class RegisterResponseDTO {
    private EncryptedDataAesCbcDTO encryptedSessionToken;
    
    private String helperAesKey;

    public EncryptedDataAesCbcDTO getEncryptedSessionToken() {
        return encryptedSessionToken;
    }

    public void setEncryptedSessionToken(EncryptedDataAesCbcDTO encryptedSessionToken) {
        this.encryptedSessionToken = encryptedSessionToken;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}
