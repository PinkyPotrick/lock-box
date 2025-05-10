package com.lockbox.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.lockbox.dto.vault.VaultDTO;
import com.lockbox.dto.vault.VaultRequestDTO;

@Component
public class VaultValidator {

    private final Logger logger = LoggerFactory.getLogger(VaultValidator.class);

    /**
     * Validate a vault request DTO
     * 
     * @param requestDTO - The encrypted request DTO to validate
     * @throws Exception If validation fails
     * @deprecated Use {@link #validateVaultDTO(VaultDTO)} instead after decryption
     */
    @Deprecated
    public void validateVaultRequest(VaultRequestDTO requestDTO) throws Exception {
        if (requestDTO == null) {
            logger.error("Vault request cannot be null");
            throw new Exception("Vault request cannot be null");
        }

        if (requestDTO.getEncryptedName() == null) {
            logger.error("Encrypted vault name is required");
            throw new Exception("Encrypted vault name is required");
        }

        if (requestDTO.getHelperAesKey() == null) {
            logger.error("Encryption key is required");
            throw new Exception("Encryption key is required");
        }
    }

    /**
     * Validate a vault DTO
     * 
     * @param vaultDTO - The decrypted vault DTO to validate
     * @throws Exception If validation fails
     */
    public void validateVaultDTO(VaultDTO vaultDTO) throws Exception {
        if (vaultDTO == null) {
            logger.error("Vault data cannot be null");
            throw new Exception("Vault data cannot be null");
        }

        if (vaultDTO.getName() == null || vaultDTO.getName().trim().isEmpty()) {
            logger.error("Vault name is required");
            throw new Exception("Vault name is required");
        }

        if (vaultDTO.getName().length() > 50) {
            logger.error("Vault name cannot exceed 50 characters");
            throw new Exception("Vault name cannot exceed 50 characters");
        }

        if (vaultDTO.getDescription() != null && vaultDTO.getDescription().length() > 200) {
            logger.error("Vault description cannot exceed 200 characters");
            throw new Exception("Vault description cannot exceed 200 characters");
        }
    }

    /**
     * Validate a vault request DTO specifically for updates
     * 
     * @param requestDTO - The encrypted update request DTO to validate
     * @throws Exception If validation fails
     */
    public void validateVaultUpdateRequest(VaultRequestDTO requestDTO) throws Exception {
        if (requestDTO == null) {
            logger.error("Vault update request cannot be null");
            throw new Exception("Vault update request cannot be null");
        }

        // For updates, at least one field should be provided
        if (requestDTO.getEncryptedName() == null && requestDTO.getEncryptedDescription() == null
                && requestDTO.getIcon() == null) {
            logger.error("At least one field must be provided for update");
            throw new Exception("At least one field must be provided for update");
        }

        // If any encrypted field is provided, the helper AES key is required
        if ((requestDTO.getEncryptedName() != null || requestDTO.getEncryptedDescription() != null)
                && requestDTO.getHelperAesKey() == null) {
            logger.error("Encryption key is required when updating encrypted fields");
            throw new Exception("Encryption key is required when updating encrypted fields");
        }
    }
}