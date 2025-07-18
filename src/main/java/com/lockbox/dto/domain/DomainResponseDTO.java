package com.lockbox.dto.domain;

import java.time.LocalDateTime;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class DomainResponseDTO {

    private String id;
    private String userId;
    private String logo;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer credentialCount;
    private EncryptedDataAesCbcDTO encryptedName;
    private EncryptedDataAesCbcDTO encryptedUrl;
    private EncryptedDataAesCbcDTO encryptedNotes;
    private String helperAesKey;

    public DomainResponseDTO() {
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

    public String getLogo() {
        return logo;
    }

    public void setLogo(String logo) {
        this.logo = logo;
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

    public EncryptedDataAesCbcDTO getEncryptedUrl() {
        return encryptedUrl;
    }

    public void setEncryptedUrl(EncryptedDataAesCbcDTO encryptedUrl) {
        this.encryptedUrl = encryptedUrl;
    }

    public EncryptedDataAesCbcDTO getEncryptedNotes() {
        return encryptedNotes;
    }

    public void setEncryptedNotes(EncryptedDataAesCbcDTO encryptedNotes) {
        this.encryptedNotes = encryptedNotes;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}