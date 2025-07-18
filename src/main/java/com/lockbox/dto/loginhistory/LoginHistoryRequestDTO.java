package com.lockbox.dto.loginhistory;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class LoginHistoryRequestDTO {

    private EncryptedDataAesCbcDTO encryptedLoginHistory;
    private String helperAesKey;

    public LoginHistoryRequestDTO() {
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