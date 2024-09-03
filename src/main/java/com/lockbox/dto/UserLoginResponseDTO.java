package com.lockbox.dto;

public class UserLoginResponseDTO {
    private String encryptedServerProofM2;

    private EncryptedDataAesCbcDTO encryptedUserPublicKey;

    private EncryptedDataAesCbcDTO encryptedUserPrivateKey;

    private EncryptedDataAesCbcDTO encryptedSessionToken;

    private String helperAuthenticateAesKey;

    public String getEncryptedServerProofM2() {
        return encryptedServerProofM2;
    }

    public void setEncryptedServerProofM2(String encryptedServerProofM2) {
        this.encryptedServerProofM2 = encryptedServerProofM2;
    }

    public EncryptedDataAesCbcDTO getEncryptedUserPublicKey() {
        return encryptedUserPublicKey;
    }

    public void setEncryptedUserPublicKey(EncryptedDataAesCbcDTO encryptedUserPublicKey) {
        this.encryptedUserPublicKey = encryptedUserPublicKey;
    }

    public EncryptedDataAesCbcDTO getEncryptedUserPrivateKey() {
        return encryptedUserPrivateKey;
    }

    public void setEncryptedUserPrivateKey(EncryptedDataAesCbcDTO encryptedUserPrivateKey) {
        this.encryptedUserPrivateKey = encryptedUserPrivateKey;
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
