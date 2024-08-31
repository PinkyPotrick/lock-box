package com.lockbox.dto;

public class UserRegistrationDTO {
    private String derivedKey;

    private String username;

    private String email;

    private String salt;

    private EncryptedDataAesCbcDTO encryptedVerifier;

    private EncryptedDataAesCbcDTO encryptedPublicKey;

    private EncryptedDataAesCbcDTO encryptedPrivateKey;

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

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public EncryptedDataAesCbcDTO getEncryptedVerifier() {
        return encryptedVerifier;
    }

    public void setEncryptedVerifier(EncryptedDataAesCbcDTO encryptedVerifier) {
        this.encryptedVerifier = encryptedVerifier;
    }

    public EncryptedDataAesCbcDTO getEncryptedPublicKey() {
        return encryptedPublicKey;
    }

    public void setEncryptedPublicKey(EncryptedDataAesCbcDTO encryptedPublicKey) {
        this.encryptedPublicKey = encryptedPublicKey;
    }

    public EncryptedDataAesCbcDTO getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public void setEncryptedPrivateKey(EncryptedDataAesCbcDTO encryptedPrivateKey) {
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}
