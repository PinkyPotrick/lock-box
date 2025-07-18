package com.lockbox.dto.credential;

import java.time.LocalDateTime;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class CredentialResponseDTO {

    private String id;
    private String userId;
    private String vaultId;
    private String domainId;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastUsed;

    // Domain info (not encrypted)
    private String domainName;
    private String domainUrl;

    // Encrypted fields
    private EncryptedDataAesCbcDTO encryptedUsername;
    private EncryptedDataAesCbcDTO encryptedEmail;
    private EncryptedDataAesCbcDTO encryptedPassword;
    private EncryptedDataAesCbcDTO encryptedNotes;
    private EncryptedDataAesCbcDTO encryptedCategory;
    private EncryptedDataAesCbcDTO encryptedFavorite;
    private String helperAesKey;

    public CredentialResponseDTO() {
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

    public String getVaultId() {
        return vaultId;
    }

    public void setVaultId(String vaultId) {
        this.vaultId = vaultId;
    }

    public String getDomainId() {
        return domainId;
    }

    public void setDomainId(String domainId) {
        this.domainId = domainId;
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

    public LocalDateTime getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(LocalDateTime lastUsed) {
        this.lastUsed = lastUsed;
    }

    public String getDomainName() {
        return domainName;
    }

    public void setDomainName(String domainName) {
        this.domainName = domainName;
    }

    public String getDomainUrl() {
        return domainUrl;
    }

    public void setDomainUrl(String domainUrl) {
        this.domainUrl = domainUrl;
    }

    public EncryptedDataAesCbcDTO getEncryptedUsername() {
        return encryptedUsername;
    }

    public void setEncryptedUsername(EncryptedDataAesCbcDTO encryptedUsername) {
        this.encryptedUsername = encryptedUsername;
    }

    public EncryptedDataAesCbcDTO getEncryptedEmail() {
        return encryptedEmail;
    }

    public void setEncryptedEmail(EncryptedDataAesCbcDTO encryptedEmail) {
        this.encryptedEmail = encryptedEmail;
    }

    public EncryptedDataAesCbcDTO getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(EncryptedDataAesCbcDTO encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public EncryptedDataAesCbcDTO getEncryptedNotes() {
        return encryptedNotes;
    }

    public void setEncryptedNotes(EncryptedDataAesCbcDTO encryptedNotes) {
        this.encryptedNotes = encryptedNotes;
    }

    public EncryptedDataAesCbcDTO getEncryptedCategory() {
        return encryptedCategory;
    }

    public void setEncryptedCategory(EncryptedDataAesCbcDTO encryptedCategory) {
        this.encryptedCategory = encryptedCategory;
    }

    public EncryptedDataAesCbcDTO getEncryptedFavorite() {
        return encryptedFavorite;
    }

    public void setEncryptedFavorite(EncryptedDataAesCbcDTO encryptedFavorite) {
        this.encryptedFavorite = encryptedFavorite;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}