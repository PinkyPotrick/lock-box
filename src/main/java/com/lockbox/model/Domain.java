package com.lockbox.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

/**
 * Entity representing a domain (website/service) that a user has credentials for. Sensitive data is stored encrypted in
 * the database.
 */
@Entity
@Table(name = "domains")
public class Domain extends BaseEntity {

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "vault_id")
    private String vaultId;

    // Store encrypted domain name in the database
    @Column(name = "name", nullable = false)
    private String name;

    // Store encrypted URL in the database
    @Column(name = "url")
    private String url;

    // Store encrypted notes in the database
    @Column(name = "notes")
    private String notes;

    // This is low sensitivity and can remain plaintext
    @Column(name = "logo")
    private String logo;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Pre-persist or constructor logic to set creation timestamp
    public void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
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
}