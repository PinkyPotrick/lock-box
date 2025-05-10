package com.lockbox.dto.authentication.registration;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class UserRegistrationResponseDTO {
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
