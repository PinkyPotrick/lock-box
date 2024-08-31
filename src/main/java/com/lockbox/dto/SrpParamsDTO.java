package com.lockbox.dto;

public class SrpParamsDTO {
    private String derivedKey;

    private String username;

    private EncryptedDataAesCbcDTO encryptedPublicKey;

    private EncryptedDataAesCbcDTO encryptedA;

    private String helperAesKey;

    public String getDerivedKey() {
        return derivedKey;
    }

    public void setDerivedKey(String derivedKey) {
        this.derivedKey = derivedKey;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public EncryptedDataAesCbcDTO getEncryptedPublicKey() {
        return encryptedPublicKey;
    }

    public void setEncryptedPublicKey(EncryptedDataAesCbcDTO encryptedPublicKey) {
        this.encryptedPublicKey = encryptedPublicKey;
    }

    public EncryptedDataAesCbcDTO getEncryptedA() {
        return encryptedA;
    }

    public void setEncryptedA(EncryptedDataAesCbcDTO encryptedA) {
        this.encryptedA = encryptedA;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}
