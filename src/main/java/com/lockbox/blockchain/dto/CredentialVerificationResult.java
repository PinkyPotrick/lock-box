package com.lockbox.blockchain.dto;

import java.time.LocalDateTime;

public class CredentialVerificationResult {
    private boolean existsOnBlockchain;
    private boolean hashMatches;
    private String storedHash;
    private LocalDateTime lastUpdated;

    public CredentialVerificationResult(boolean existsOnBlockchain, boolean hashMatches, String storedHash,
            LocalDateTime lastUpdated) {
        this.existsOnBlockchain = existsOnBlockchain;
        this.hashMatches = hashMatches;
        this.storedHash = storedHash;
        this.lastUpdated = lastUpdated;
    }

    public boolean isExistsOnBlockchain() {
        return existsOnBlockchain;
    }

    public void setExistsOnBlockchain(boolean existsOnBlockchain) {
        this.existsOnBlockchain = existsOnBlockchain;
    }

    public boolean isHashMatches() {
        return hashMatches;
    }

    public void setHashMatches(boolean hashMatches) {
        this.hashMatches = hashMatches;
    }

    public String getStoredHash() {
        return storedHash;
    }

    public void setStoredHash(String storedHash) {
        this.storedHash = storedHash;
    }

    public LocalDateTime getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(LocalDateTime lastUpdated) {
        this.lastUpdated = lastUpdated;
    }
}