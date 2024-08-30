package com.lockbox.model;

import com.lockbox.utils.EncryptionUtils;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "credentials")
public class Credential extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "vault_id", nullable = false)
    private Vault vault;

    @Column(nullable = false, length = 1024)
    private String website;

    @Column(nullable = false, length = 1024)
    private String username;

    @Column(nullable = false, length = 1024)
    private String password;

    @Column(length = 4500)
    private String note;

    // Getters and Setters with encryption/decryption

    public String getWebsite() {
        return EncryptionUtils.decrypt(website);
    }

    public void setWebsite(String website) {
        this.website = EncryptionUtils.encrypt(website);
    }

    public String getUsername() {
        return EncryptionUtils.decrypt(username);
    }

    public void setUsername(String username) {
        this.username = EncryptionUtils.encrypt(username);
    }

    public String getPassword() {
        return EncryptionUtils.decrypt(password);
    }

    public void setPassword(String password) {
        this.password = EncryptionUtils.encrypt(password);
    }

    public String getNote() {
        return note == null ? null : EncryptionUtils.decrypt(note);
    }

    public void setNote(String note) {
        this.note = note == null ? null : EncryptionUtils.encrypt(note);
    }
}
