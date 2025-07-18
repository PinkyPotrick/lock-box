package com.lockbox.dto.domain;

import java.time.LocalDateTime;

/**
 * Data transfer object for Domain entity. Contains the decrypted domain data.
 */
public class DomainDTO {

    private String id;
    private String userId;
    private String name;
    private String url;
    private String notes;
    private String logo;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Integer credentialCount;

    public DomainDTO() {
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

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
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
}