package com.lockbox.dto.vault;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class VaultRequestDTO {

    private String userId;
    private String icon;
    private EncryptedDataAesCbcDTO encryptedName;
    private EncryptedDataAesCbcDTO encryptedDescription;
    private String helperAesKey;

    public VaultRequestDTO() {
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }

    public EncryptedDataAesCbcDTO getEncryptedName() {
        return encryptedName;
    }

    public void setEncryptedName(EncryptedDataAesCbcDTO encryptedName) {
        this.encryptedName = encryptedName;
    }

    public EncryptedDataAesCbcDTO getEncryptedDescription() {
        return encryptedDescription;
    }

    public void setEncryptedDescription(EncryptedDataAesCbcDTO encryptedDescription) {
        this.encryptedDescription = encryptedDescription;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}