package com.lockbox.model;

import java.time.LocalDate;

import com.lockbox.utils.EncryptionUtils;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name = "users")
public class User extends BaseEntity {

    @Column(nullable = false, length = 1024)
    private String username;

    @Column(nullable = false, length = 1024)
    private String email;

    @Column(nullable = false, length = 1024)
    private String salt;

    @Column(nullable = false, length = 1024)
    private String verifier;

    @Column(nullable = false, length = 1024)
    private String createdAt;

    // Getters and Setters with encryption/decryption

    public String getUsername() {
        return EncryptionUtils.decrypt(username);
    }

    public void setUsername(String username) {
        this.username = EncryptionUtils.encrypt(username);
    }

    public String getEmail() {
        return EncryptionUtils.decrypt(email);
    }

    public void setEmail(String email) {
        this.email = EncryptionUtils.encrypt(email);
    }

    public String getSalt() {
        return EncryptionUtils.decrypt(salt);
    }

    public void setSalt(String salt) {
        this.salt = EncryptionUtils.encrypt(salt);
    }

    public String getVerifier() {
        return EncryptionUtils.decrypt(verifier);
    }

    public void setVerifier(String verifier) {
        this.verifier = EncryptionUtils.encrypt(verifier);
    }

    public LocalDate getCreatedAt() {
        return LocalDate.parse(EncryptionUtils.decrypt(createdAt));
    }

    public void setCreatedAt(LocalDate createdAt) {
        this.createdAt = EncryptionUtils.encrypt(createdAt.toString());
    }
}