package com.lockbox.validators;

import org.springframework.stereotype.Component;

import com.lockbox.dto.domain.DomainDTO;
import com.lockbox.dto.domain.DomainRequestDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.FieldNames;
import com.lockbox.utils.AppConstants.MaxLengths;
import com.lockbox.utils.AppConstants.ValidationErrors;

/**
 * Validator for domain-related DTOs.
 */
@Component
public class DomainValidator extends BaseValidator {

    /**
     * Creates a new domain validator.
     */
    public DomainValidator() {
        super(AppConstants.EntityTypes.DOMAIN);
    }

    /**
     * Validate a domain request DTO
     * 
     * @param requestDTO - The encrypted request DTO to validate
     * @throws ValidationException If validation fails
     * @deprecated Use {@link #validateDomainDTO(DomainDTO)} instead after decryption
     */
    @Deprecated
    public void validateDomainRequest(DomainRequestDTO requestDTO) throws ValidationException {
        validateNotNull(requestDTO, FieldNames.DOMAIN_REQUEST);
        validateNotNull(requestDTO.getEncryptedName(), FieldNames.NAME, ValidationErrors.DOMAIN_NAME_REQUIRED);
        validateNotNull(requestDTO.getHelperAesKey(), FieldNames.ENCRYPTION_KEY,
                ValidationErrors.ENCRYPTION_KEY_REQUIRED);
    }

    /**
     * Validate a domain DTO
     * 
     * @param domainDTO - The decrypted domain DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateDomainDTO(DomainDTO domainDTO) throws ValidationException {
        validateNotNull(domainDTO, FieldNames.DOMAIN_DATA);
        validateRequired(domainDTO.getName(), FieldNames.NAME, ValidationErrors.DOMAIN_NAME_REQUIRED);
        validateMaxLength(domainDTO.getName(), MaxLengths.NAME, FieldNames.NAME);

        if (hasContent(domainDTO.getUrl())) {
            validateMaxLength(domainDTO.getUrl(), MaxLengths.URL, FieldNames.URL);
        }

        if (hasContent(domainDTO.getNotes())) {
            validateMaxLength(domainDTO.getNotes(), MaxLengths.NOTES, FieldNames.NOTES);
        }
    }

    /**
     * Validate a domain update request DTO
     * 
     * @param requestDTO - The encrypted update request DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateDomainUpdateRequest(DomainRequestDTO requestDTO) throws ValidationException {
        validateNotNull(requestDTO, FieldNames.DOMAIN_REQUEST);

        // For updates, at least one field should be provided
        boolean hasUpdateFields = requestDTO.getEncryptedName() != null || requestDTO.getEncryptedUrl() != null
                || requestDTO.getEncryptedNotes() != null || requestDTO.getLogo() != null;

        if (!hasUpdateFields) {
            throwValidationException(ValidationErrors.UPDATE_AT_LEAST_ONE);
        }

        // If any encrypted field is provided, the helper AES key is required
        boolean hasEncryptedFields = requestDTO.getEncryptedName() != null || requestDTO.getEncryptedUrl() != null
                || requestDTO.getEncryptedNotes() != null;

        if (hasEncryptedFields && requestDTO.getHelperAesKey() == null) {
            throwValidationException(ValidationErrors.ENCRYPTION_KEY_REQUIRED);
        }
    }
}