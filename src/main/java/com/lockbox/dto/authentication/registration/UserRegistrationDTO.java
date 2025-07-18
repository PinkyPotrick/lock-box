package com.lockbox.dto.authentication.registration;

public class UserRegistrationDTO {
    private String derivedUsername;

    private String email;

    private String salt;

    private String clientVerifier;

    private String clientPublicKey;

    private String clientPrivateKey;

    private String derivedKey;

    public String getDerivedUsername() {
        return derivedUsername;
    }

    public void setDerivedUsername(String derviedUsername) {
        this.derivedUsername = derviedUsername;
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

    public String getClientVerifier() {
        return clientVerifier;
    }

    public void setClientVerifier(String clientVerifier) {
        this.clientVerifier = clientVerifier;
    }

    public String getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(String clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public String getClientPrivateKey() {
        return clientPrivateKey;
    }

    public void setClientPrivateKey(String clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public String getDerivedKey() {
        return derivedKey;
    }

    public void setDerivedKey(String derivedKey) {
        this.derivedKey = derivedKey;
    }
}
