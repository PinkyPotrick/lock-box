package com.lockbox.validators;

import org.springframework.stereotype.Component;

import com.lockbox.model.Credential;

@Component
public class CredentialValidator {

    /**
     * Validate credential data
     * 
     * @param credential The credential to validate
     * @throws Exception If validation fails
     */
    public void validate(Credential credential) throws Exception {
        if (credential == null) {
            throw new Exception("Credential cannot be null");
        }

        // Validate required fields
        if (credential.getUserId() == null || credential.getUserId().trim().isEmpty()) {
            throw new Exception("User ID is required");
        }

        if (credential.getDomainId() == null || credential.getDomainId().trim().isEmpty()) {
            throw new Exception("Domain ID is required");
        }

        if (credential.getVaultId() == null || credential.getVaultId().trim().isEmpty()) {
            throw new Exception("Vault ID is required");
        }

        if (credential.getUsername() == null || credential.getUsername().trim().isEmpty()) {
            throw new Exception("Username is required");
        }

        if (credential.getPassword() == null || credential.getPassword().trim().isEmpty()) {
            throw new Exception("Password is required");
        }
    }
}