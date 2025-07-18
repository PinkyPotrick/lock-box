package com.lockbox.dto.authentication.password;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class PasswordChangeInitResponseDTO {
    private EncryptedDataAesCbcDTO encryptedServerPublicValueB;
    private String helperAesKey;
    private String salt;

    public EncryptedDataAesCbcDTO getEncryptedServerPublicValueB() {
        return encryptedServerPublicValueB;
    }

    public void setEncryptedServerPublicValueB(EncryptedDataAesCbcDTO encryptedServerPublicValueB) {
        this.encryptedServerPublicValueB = encryptedServerPublicValueB;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}