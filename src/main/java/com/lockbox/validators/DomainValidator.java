package com.lockbox.validators;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.lockbox.dto.domain.DomainDTO;
import com.lockbox.dto.domain.DomainRequestDTO;

/**
 * Validator for domain-related DTOs.
 */
@Component
public class DomainValidator {

    private final Logger logger = LoggerFactory.getLogger(DomainValidator.class);

    /**
     * Validate a domain request DTO
     * 
     * @param requestDTO - The encrypted request DTO to validate
     * @throws Exception If validation fails
     * @deprecated Use {@link #validateDomainDTO(DomainDTO)} instead after decryption
     */
    @Deprecated
    public void validateDomainRequest(DomainRequestDTO requestDTO) throws Exception {
        if (requestDTO == null) {
            logger.error("Domain request cannot be null");
            throw new Exception("Domain request cannot be null");
        }

        if (requestDTO.getEncryptedName() == null) {
            logger.error("Encrypted domain name is required");
            throw new Exception("Encrypted domain name is required");
        }

        if (requestDTO.getHelperAesKey() == null) {
            logger.error("Encryption key is required");
            throw new Exception("Encryption key is required");
        }
    }

    /**
     * Validate a domain DTO
     * 
     * @param domainDTO - The decrypted domain DTO to validate
     * @throws Exception If validation fails
     */
    public void validateDomainDTO(DomainDTO domainDTO) throws Exception {
        if (domainDTO == null) {
            logger.error("Domain data cannot be null");
            throw new Exception("Domain data cannot be null");
        }

        if (domainDTO.getName() == null || domainDTO.getName().trim().isEmpty()) {
            logger.error("Domain name is required");
            throw new Exception("Domain name is required");
        }

        if (domainDTO.getName().length() > 100) {
            logger.error("Domain name cannot exceed 100 characters");
            throw new Exception("Domain name cannot exceed 100 characters");
        }

        if (domainDTO.getUrl() != null && domainDTO.getUrl().length() > 2000) {
            logger.error("URL cannot exceed 2000 characters");
            throw new Exception("URL cannot exceed 2000 characters");
        }

        if (domainDTO.getNotes() != null && domainDTO.getNotes().length() > 1000) {
            logger.error("Notes cannot exceed 1000 characters");
            throw new Exception("Notes cannot exceed 1000 characters");
        }
    }

    /**
     * Validate a domain update request DTO
     * 
     * @param requestDTO - The encrypted update request DTO to validate
     * @throws Exception If validation fails
     */
    public void validateDomainUpdateRequest(DomainRequestDTO requestDTO) throws Exception {
        if (requestDTO == null) {
            logger.error("Domain update request cannot be null");
            throw new Exception("Domain update request cannot be null");
        }

        // For updates, at least one field should be provided
        if (requestDTO.getEncryptedName() == null && requestDTO.getEncryptedUrl() == null
                && requestDTO.getEncryptedNotes() == null && requestDTO.getLogo() == null) {
            logger.error("At least one field must be provided for update");
            throw new Exception("At least one field must be provided for update");
        }

        // If any encrypted field is provided, the helper AES key is required
        if ((requestDTO.getEncryptedName() != null || requestDTO.getEncryptedUrl() != null
                || requestDTO.getEncryptedNotes() != null) && requestDTO.getHelperAesKey() == null) {
            logger.error("Encryption key is required when updating encrypted fields");
            throw new Exception("Encryption key is required when updating encrypted fields");
        }
    }
}