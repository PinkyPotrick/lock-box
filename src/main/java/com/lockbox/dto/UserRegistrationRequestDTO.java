package com.lockbox.dto;

public class UserRegistrationRequestDTO {
    private String derivedKey;

    private String encryptedDerivedUsername;

    private String encryptedEmail;

    private String encryptedSalt;

    private EncryptedDataAesCbcDTO encryptedClientVerifier;

    private EncryptedDataAesCbcDTO encryptedClientPublicKey;

    private EncryptedDataAesCbcDTO encryptedClientPrivateKey;

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

    public void setEncryptedDerivedUsername(String username) {
        this.encryptedDerivedUsername = username;
    }

    public String getEncryptedEmail() {
        return encryptedEmail;
    }

    public void setEncryptedEmail(String email) {
        this.encryptedEmail = email;
    }

    public String getEncryptedSalt() {
        return encryptedSalt;
    }

    public void setEncryptedSalt(String salt) {
        this.encryptedSalt = salt;
    }

    public EncryptedDataAesCbcDTO getEncryptedClientVerifier() {
        return encryptedClientVerifier;
    }

    public void setEncryptedClientVerifier(EncryptedDataAesCbcDTO encryptedClientVerifier) {
        this.encryptedClientVerifier = encryptedClientVerifier;
    }

    public EncryptedDataAesCbcDTO getEncryptedClientPublicKey() {
        return encryptedClientPublicKey;
    }

    public void setEncryptedClientPublicKey(EncryptedDataAesCbcDTO encryptedClientPublicKey) {
        this.encryptedClientPublicKey = encryptedClientPublicKey;
    }

    public EncryptedDataAesCbcDTO getEncryptedClientPrivateKey() {
        return encryptedClientPrivateKey;
    }

    public void setEncryptedClientPrivateKey(EncryptedDataAesCbcDTO encryptedClientPrivateKey) {
        this.encryptedClientPrivateKey = encryptedClientPrivateKey;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}
