package com.lockbox.model;

import java.time.LocalDate;

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

    @Column(nullable = false, length = 2048)
    private String publicKey;

    @Column(nullable = false, length = 2048)
    private String privateKey;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getVerifier() {
        return verifier;
    }

    public void setVerifier(String verifier) {
        this.verifier = verifier;
    }

    public LocalDate getCreatedAt() {
        return LocalDate.parse(createdAt);
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt.toString();
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }
}