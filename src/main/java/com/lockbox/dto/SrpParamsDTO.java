package com.lockbox.dto;

public class SrpParamsDTO {
    private String derivedKey;

    private String username;

    private EncryptedDataAesCbcDTO encryptedClientPublicKey;

    private EncryptedDataAesCbcDTO encryptedClientPublicValueA;

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
