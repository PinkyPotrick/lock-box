package com.lockbox.dto.authentication.password;

public class PasswordChangeCompleteResponseDTO {
    private String encryptedServerProofM2;
    private boolean success;

    public String getEncryptedServerProofM2() {
        return encryptedServerProofM2;
    }

    public void setEncryptedServerProofM2(String encryptedServerProofM2) {
        this.encryptedServerProofM2 = encryptedServerProofM2;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }
}