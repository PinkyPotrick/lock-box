package com.lockbox.dto.authentication.srp;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

/**
 * The encrypted SRP parameters received from frontend.
 */
public class SrpParamsRequestDTO {
    private String derivedKey;

    private String encryptedDerivedUsername;

    private EncryptedDataAesCbcDTO encryptedClientPublicKey;

    private EncryptedDataAesCbcDTO encryptedClientPublicValueA;

    private String helperAesKey;

    public String getDerivedKey() {
        return derivedKey;
    }

    public void setDerivedKey(String derivedKey) {
        this.derivedKey = derivedKey;
    }

    public String getEncryptedDerivedUsername() {
        return encryptedDerivedUsername;
    }

    public void setEncryptedDerivedUsername(String encryptedDerivedUsername) {
        this.encryptedDerivedUsername = encryptedDerivedUsername;
    }

    public EncryptedDataAesCbcDTO getEncryptedClientPublicKey() {
        return encryptedClientPublicKey;
    }

    public void setEncryptedClientPublicKey(EncryptedDataAesCbcDTO encryptedClientPublicKey) {
        this.encryptedClientPublicKey = encryptedClientPublicKey;
    }

    public EncryptedDataAesCbcDTO getEncryptedClientPublicValueA() {
        return encryptedClientPublicValueA;
    }

    public void setEncryptedClientPublicValueA(EncryptedDataAesCbcDTO encryptedClientPublicValueA) {
        this.encryptedClientPublicValueA = encryptedClientPublicValueA;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}
