package com.lockbox.dto;

public class UserRegistrationDTO {
    private String derivedKey;

    private String username;

    private String email;

    private String salt;

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
