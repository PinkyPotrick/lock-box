package com.lockbox.dto.loginhistory;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class LoginHistoryResponseDTO {

    private EncryptedDataAesCbcDTO encryptedLoginHistory;
    private String helperAesKey;

    public LoginHistoryResponseDTO() {
    }

    public EncryptedDataAesCbcDTO getEncryptedLoginHistory() {
        return encryptedLoginHistory;
    }

    public void setEncryptedLoginHistory(EncryptedDataAesCbcDTO encryptedLoginHistory) {
        this.encryptedLoginHistory = encryptedLoginHistory;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}