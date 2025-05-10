package com.lockbox.dto.vault;

import java.time.LocalDateTime;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class VaultResponseDTO {

    private String id;
    private String userId;
    private String icon;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer credentialCount;
    private EncryptedDataAesCbcDTO encryptedName;
    private EncryptedDataAesCbcDTO encryptedDescription;
    private String helperAesKey;

    public VaultResponseDTO() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public Integer getCredentialCount() {
        return credentialCount;
    }

    public void setCredentialCount(Integer credentialCount) {
        this.credentialCount = credentialCount;
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