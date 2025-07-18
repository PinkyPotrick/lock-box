package com.lockbox.blockchain.dto;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * DTO for returning detailed blockchain information about a credential. Used for administrative and demonstration
 * purposes.
 */
public class BlockchainCredentialDetailsDTO {
    private String credentialId;
    private String vaultId;
    private String ownerId;
    private boolean existsOnBlockchain;
    private boolean verified;
    private String storedHash;
    private String currentHash;
    private LocalDateTime lastUpdated;
    private String errorMessage;
    private Map<String, Object> metadata = new HashMap<>();

    public String getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
    }

    public String getVaultId() {
        return vaultId;
    }

    public void setVaultId(String vaultId) {
        this.vaultId = vaultId;
    }

    public String getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(String ownerId) {
        this.ownerId = ownerId;
    }

    public boolean isExistsOnBlockchain() {
        return existsOnBlockchain;
    }

    public void setExistsOnBlockchain(boolean existsOnBlockchain) {
        this.existsOnBlockchain = existsOnBlockchain;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public String getStoredHash() {
        return storedHash;
    }

    public void setStoredHash(String storedHash) {
        this.storedHash = storedHash;
    }

    public String getCurrentHash() {
        return currentHash;
    }

    public void setCurrentHash(String currentHash) {
        this.currentHash = currentHash;
    }

    public LocalDateTime getLastUpdated() {
        return lastUpdated;
    }

    public void setLastUpdated(LocalDateTime lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }
}