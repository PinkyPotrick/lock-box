package com.lockbox.dto;

/**
 * The encrypted user login data received from frontend.
 */
public class UserLoginRequestDTO {
    private String encryptedClientProofM1;

    public String getEncryptedClientProofM1() {
        return encryptedClientProofM1;
    }

    public void setEncryptedClientProofM1(String encryptedClientProofM1) {
        this.encryptedClientProofM1 = encryptedClientProofM1;
    }
}
