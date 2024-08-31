package com.lockbox.model;

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

    public String getWebsite() {
        return website;
    }

    public void setWebsite(String website) {
        this.website = website;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }
}
