package com.lockbox.model;

import com.lockbox.utils.EncryptionUtils;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "vaults")
public class Vault extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 1024)
    private String name;

    @Column(length = 4500)
    private String description;

    // Getters and Setters with encryption/decryption

    public String getName() {
        return EncryptionUtils.decrypt(name);
    }

    public void setName(String name) {
        this.name = EncryptionUtils.encrypt(name);
    }

    public String getDescription() {
        return description == null ? null : EncryptionUtils.decrypt(description);
    }

    public void setDescription(String description) {
        this.description = description == null ? null : EncryptionUtils.encrypt(description);
    }
}