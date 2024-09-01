package com.lockbox.dto;

public class UserLoginDTO {
    private String encryptedClientProofM;

    public String getEncryptedClientProofM() {
        return encryptedClientProofM;
    }

    public void setEncryptedClientProofM(String encryptedClientProofM) {
        this.encryptedClientProofM = encryptedClientProofM;
    }
}
