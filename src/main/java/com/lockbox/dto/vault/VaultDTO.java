package com.lockbox.dto.vault;

import java.time.LocalDateTime;

public class VaultDTO {

    private String id;
    private String userId;
    private String name;
    private String description;
    private String icon;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer credentialCount;

    public VaultDTO() {
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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
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
}