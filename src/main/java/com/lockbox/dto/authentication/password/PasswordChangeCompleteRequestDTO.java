package com.lockbox.dto.authentication.password;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class PasswordChangeCompleteRequestDTO {
    private String encryptedClientProofM1;
    private String encryptedNewSalt;
    private String encryptedNewDerivedKey;
    private String encryptedNewDerivedUsername;
    private EncryptedDataAesCbcDTO encryptedNewVerifier;
    private String helperAesKey;

    public String getEncryptedClientProofM1() {
        return encryptedClientProofM1;
    }

    public void setEncryptedClientProofM1(String encryptedClientProofM1) {
        this.encryptedClientProofM1 = encryptedClientProofM1;
    }

    public String getEncryptedNewSalt() {
        return encryptedNewSalt;
    }

    public void setEncryptedNewSalt(String encryptedNewSalt) {
        this.encryptedNewSalt = encryptedNewSalt;
    }

    public String getEncryptedNewDerivedKey() {
        return encryptedNewDerivedKey;
    }

    public void setEncryptedNewDerivedKey(String encryptedNewDerivedKey) {
        this.encryptedNewDerivedKey = encryptedNewDerivedKey;
    }

    public String getEncryptedNewDerivedUsername() {
        return encryptedNewDerivedUsername;
    }

    public void setEncryptedNewDerivedUsername(String encryptedNewDerivedUsername) {
        this.encryptedNewDerivedUsername = encryptedNewDerivedUsername;
    }

    public EncryptedDataAesCbcDTO getEncryptedNewVerifier() {
        return encryptedNewVerifier;
    }

    public void setEncryptedNewVerifier(EncryptedDataAesCbcDTO encryptedNewVerifier) {
        this.encryptedNewVerifier = encryptedNewVerifier;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}