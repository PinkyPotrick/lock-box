package com.lockbox.dto;

public class UserLoginResponseDTO {
    private String encryptedServerProofM;

    private EncryptedDataAesCbcDTO encryptedSessionToken;

    private String helperAuthenticateAesKey;

    public String getEncryptedServerProofM() {
        return encryptedServerProofM;
    }

    public void setEncryptedServerProofM(String encryptedServerProofM) {
        this.encryptedServerProofM = encryptedServerProofM;
    }

    public EncryptedDataAesCbcDTO getEncryptedSessionToken() {
        return encryptedSessionToken;
    }

    public void setEncryptedSessionToken(EncryptedDataAesCbcDTO encryptedSessionToken) {
        this.encryptedSessionToken = encryptedSessionToken;
    }

    public String getHelperAuthenticateAesKey() {
        return helperAuthenticateAesKey;
    }

    public void setHelperAuthenticateAesKey(String helperAuthenticateAesKey) {
        this.helperAuthenticateAesKey = helperAuthenticateAesKey;
    }
}
