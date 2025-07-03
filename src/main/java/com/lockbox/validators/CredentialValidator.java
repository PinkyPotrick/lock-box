package com.lockbox.validators;

import org.springframework.stereotype.Component;

import com.lockbox.dto.credential.CredentialDTO;
import com.lockbox.dto.credential.CredentialRequestDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.model.enums.CredentialCategory;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.FieldNames;
import com.lockbox.utils.AppConstants.MaxLengths;
import com.lockbox.utils.AppConstants.ValidationErrors;

@Component
public class CredentialValidator extends BaseValidator {

    public CredentialValidator() {
        super(AppConstants.EntityTypes.CREDENTIAL);
    }

    /**
     * Validate a credential request DTO
     * 
     * @param requestDTO - The encrypted request DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateCredentialRequest(CredentialRequestDTO requestDTO) throws ValidationException {
        validateNotNull(requestDTO, FieldNames.CREDENTIAL_REQUEST);
        validateNotNull(requestDTO.getEncryptedUsername(), FieldNames.USERNAME, ValidationErrors.USERNAME_REQUIRED);
        validateNotNull(requestDTO.getEncryptedPassword(), FieldNames.PASSWORD, ValidationErrors.PASSWORD_REQUIRED);
        validateNotNull(requestDTO.getHelperAesKey(), FieldNames.ENCRYPTION_KEY,
                ValidationErrors.ENCRYPTION_KEY_REQUIRED);

        validateId(requestDTO.getDomainId(), FieldNames.DOMAIN_ID);
        validateId(requestDTO.getVaultId(), FieldNames.VAULT_ID);
    }

    /**
     * Validate a credential DTO
     * 
     * @param credentialDTO - The decrypted credential DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateCredentialDTO(CredentialDTO credentialDTO) throws ValidationException {
        validateNotNull(credentialDTO, FieldNames.CREDENTIAL_DATA);

        validateRequired(credentialDTO.getUsername(), FieldNames.USERNAME, ValidationErrors.USERNAME_REQUIRED);
        validateMaxLength(credentialDTO.getUsername(), MaxLengths.USERNAME, FieldNames.USERNAME);
        validateSecure(credentialDTO.getUsername(), FieldNames.USERNAME);

        validateRequired(credentialDTO.getPassword(), FieldNames.PASSWORD, ValidationErrors.PASSWORD_REQUIRED);
        validateMaxLength(credentialDTO.getPassword(), MaxLengths.PASSWORD, FieldNames.PASSWORD);
        validateSecure(credentialDTO.getPassword(), FieldNames.PASSWORD);

        validateMaxLength(credentialDTO.getEmail(), MaxLengths.EMAIL, FieldNames.EMAIL);
        validateSecure(credentialDTO.getEmail(), FieldNames.EMAIL);

        validateMaxLength(credentialDTO.getNotes(), MaxLengths.NOTES, FieldNames.NOTES);
        validateSecure(credentialDTO.getNotes(), FieldNames.NOTES);

        // Validate category if provided
        if (hasContent(credentialDTO.getCategory())) {
            validateCredentialCategory(credentialDTO.getCategory());
            validateMaxLength(credentialDTO.getCategory(), MaxLengths.CATEGORY, FieldNames.CATEGORY);
            validateSecure(credentialDTO.getCategory(), FieldNames.CATEGORY);
        }

        validateId(credentialDTO.getDomainId(), FieldNames.DOMAIN_ID);
        validateSecure(credentialDTO.getDomainId(), FieldNames.DOMAIN_ID);

        validateId(credentialDTO.getVaultId(), FieldNames.VAULT_ID);
        validateSecure(credentialDTO.getVaultId(), FieldNames.VAULT_ID);
    }

    /**
     * Validate a credential request DTO specifically for updates
     * 
     * @param requestDTO - The encrypted update request DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateCredentialUpdateRequest(CredentialRequestDTO requestDTO) throws ValidationException {
        validateNotNull(requestDTO, FieldNames.CREDENTIAL_UPDATE);

        // Check if at least one field is provided for update
        boolean hasUpdateFields = requestDTO.getEncryptedUsername() != null || requestDTO.getEncryptedPassword() != null
                || requestDTO.getEncryptedEmail() != null || requestDTO.getEncryptedNotes() != null
                || requestDTO.getEncryptedCategory() != null || requestDTO.getEncryptedFavorite() != null;

        if (!hasUpdateFields) {
            throwValidationException(ValidationErrors.UPDATE_AT_LEAST_ONE);
        }

        // If any encrypted field is provided, helper key is required
        if (hasUpdateFields && requestDTO.getHelperAesKey() == null) {
            throwValidationException(ValidationErrors.ENCRYPTION_KEY_REQUIRED);
        }
    }

    /**
     * Validate that a category is in the allowed list
     * 
     * @param category - The category to validate
     * @throws ValidationException if the category is invalid
     */
    private void validateCredentialCategory(String category) {
        if (!CredentialCategory.isValid(category)) {
            logger.error("Invalid category: {}", category);
            String allowedCategories = String.join(", ", CredentialCategory.getAllDisplayNames());
            throwValidationException(ValidationErrors.INVALID_CATEGORY.replace("{0}", allowedCategories));
        }
    }
}