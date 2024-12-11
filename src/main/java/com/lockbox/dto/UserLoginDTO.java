package com.lockbox.dto;

/**
 * The decrypted user login data handled on backend.
 */
public class UserLoginDTO {
    private String eclientProofM1;

    public String getEclientProofM1() {
        return eclientProofM1;
    }

    public void setEclientProofM1(String eclientProofM1) {
        this.eclientProofM1 = eclientProofM1;
    }
}
