package com.lockbox.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.lockbox.dto.credential.CredentialDTO;
import com.lockbox.dto.credential.CredentialRequestDTO;

@Component
public class CredentialValidator {

    private final Logger logger = LoggerFactory.getLogger(CredentialValidator.class);

    /**
     * Validate a credential request DTO
     * 
     * @param requestDTO - The encrypted request DTO to validate
     * @throws Exception If validation fails
     */
    public void validateCredentialRequest(CredentialRequestDTO requestDTO) throws Exception {
        if (requestDTO == null) {
            logger.error("Credential request cannot be null");
            throw new Exception("Credential request cannot be null");
        }

        if (requestDTO.getEncryptedUsername() == null) {
            logger.error("Encrypted username is required");
            throw new Exception("Encrypted username is required");
        }

        if (requestDTO.getEncryptedPassword() == null) {
            logger.error("Encrypted password is required");
            throw new Exception("Encrypted password is required");
        }

        if (requestDTO.getHelperAesKey() == null) {
            logger.error("Encryption key is required");
            throw new Exception("Encryption key is required");
        }

        if (requestDTO.getDomainId() == null || requestDTO.getDomainId().trim().isEmpty()) {
            logger.error("Domain ID is required");
            throw new Exception("Domain ID is required");
        }

        if (requestDTO.getVaultId() == null || requestDTO.getVaultId().trim().isEmpty()) {
            logger.error("Vault ID is required");
            throw new Exception("Vault ID is required");
        }
    }

    /**
     * Validate a credential DTO
     * 
     * @param credentialDTO - The decrypted credential DTO to validate
     * @throws Exception If validation fails
     */
    public void validateCredentialDTO(CredentialDTO credentialDTO) throws Exception {
        if (credentialDTO == null) {
            logger.error("Credential data cannot be null");
            throw new Exception("Credential data cannot be null");
        }

        if (credentialDTO.getUsername() == null || credentialDTO.getUsername().trim().isEmpty()) {
            logger.error("Username is required");
            throw new Exception("Username is required");
        }

        if (credentialDTO.getUsername().length() > 255) {
            logger.error("Username cannot exceed 255 characters");
            throw new Exception("Username cannot exceed 255 characters");
        }

        if (credentialDTO.getPassword() == null || credentialDTO.getPassword().trim().isEmpty()) {
            logger.error("Password is required");
            throw new Exception("Password is required");
        }

        if (credentialDTO.getPassword().length() > 255) {
            logger.error("Password cannot exceed 255 characters");
            throw new Exception("Password cannot exceed 255 characters");
        }

        if (credentialDTO.getEmail() != null && credentialDTO.getEmail().length() > 255) {
            logger.error("Email cannot exceed 255 characters");
            throw new Exception("Email cannot exceed 255 characters");
        }

        if (credentialDTO.getNotes() != null && credentialDTO.getNotes().length() > 2000) {
            logger.error("Notes cannot exceed 2000 characters");
            throw new Exception("Notes cannot exceed 2000 characters");
        }

        if (credentialDTO.getCategory() != null && credentialDTO.getCategory().length() > 100) {
            logger.error("Category cannot exceed 100 characters");
            throw new Exception("Category cannot exceed 100 characters");
        }

        if (credentialDTO.getDomainId() == null || credentialDTO.getDomainId().trim().isEmpty()) {
            logger.error("Domain ID is required");
            throw new Exception("Domain ID is required");
        }

        if (credentialDTO.getVaultId() == null || credentialDTO.getVaultId().trim().isEmpty()) {
            logger.error("Vault ID is required");
            throw new Exception("Vault ID is required");
        }
    }

    /**
     * Validate a credential request DTO specifically for updates
     * 
     * @param requestDTO - The encrypted update request DTO to validate
     * @throws Exception If validation fails
     */
    public void validateCredentialUpdateRequest(CredentialRequestDTO requestDTO) throws Exception {
        if (requestDTO == null) {
            logger.error("Credential update request cannot be null");
            throw new Exception("Credential update request cannot be null");
        }

        // For updates, at least one field should be provided
        if (requestDTO.getEncryptedUsername() == null && requestDTO.getEncryptedPassword() == null
                && requestDTO.getEncryptedEmail() == null && requestDTO.getEncryptedNotes() == null
                && requestDTO.getEncryptedCategory() == null && requestDTO.getEncryptedFavorite() == null) {
            logger.error("At least one field must be provided for update");
            throw new Exception("At least one field must be provided for update");
        }

        // If any encrypted field is provided, the helper AES key is required
        if ((requestDTO.getEncryptedUsername() != null || requestDTO.getEncryptedPassword() != null
                || requestDTO.getEncryptedEmail() != null || requestDTO.getEncryptedNotes() != null
                || requestDTO.getEncryptedCategory() != null || requestDTO.getEncryptedFavorite() != null)
                && requestDTO.getHelperAesKey() == null) {
            logger.error("Encryption key is required when updating encrypted fields");
            throw new Exception("Encryption key is required when updating encrypted fields");
        }
    }
}