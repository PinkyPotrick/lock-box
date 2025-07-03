package com.lockbox.validators;

import org.springframework.stereotype.Component;

import com.lockbox.dto.vault.VaultDTO;
import com.lockbox.dto.vault.VaultRequestDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.FieldNames;
import com.lockbox.utils.AppConstants.MaxLengths;
import com.lockbox.utils.AppConstants.ValidationErrors;

/**
 * Validator for vault-related DTOs.
 */
@Component
public class VaultValidator extends BaseValidator {

    /**
     * Creates a new vault validator.
     */
    public VaultValidator() {
        super(AppConstants.EntityTypes.VAULT);
    }

    /**
     * Validate a vault request DTO
     * 
     * @param requestDTO - The encrypted request DTO to validate
     * @throws ValidationException If validation fails
     * @deprecated Use {@link #validateVaultDTO(VaultDTO)} instead after decryption
     */
    @Deprecated
    public void validateVaultRequest(VaultRequestDTO requestDTO) throws ValidationException {
        validateNotNull(requestDTO, FieldNames.VAULT_REQUEST);
        validateNotNull(requestDTO.getEncryptedName(), FieldNames.NAME, ValidationErrors.VAULT_NAME_REQUIRED);
        validateNotNull(requestDTO.getHelperAesKey(), FieldNames.ENCRYPTION_KEY,
                ValidationErrors.ENCRYPTION_KEY_REQUIRED);
    }

    /**
     * Validate a vault DTO
     * 
     * @param vaultDTO - The decrypted vault DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateVaultDTO(VaultDTO vaultDTO) throws ValidationException {
        validateNotNull(vaultDTO, FieldNames.VAULT_DATA);
        validateRequired(vaultDTO.getName(), FieldNames.NAME, ValidationErrors.VAULT_NAME_REQUIRED);
        validateMaxLength(vaultDTO.getName(), MaxLengths.NAME, FieldNames.NAME);
        validateSecure(vaultDTO.getName(), FieldNames.NAME);

        if (hasContent(vaultDTO.getDescription())) {
            validateMaxLength(vaultDTO.getDescription(), MaxLengths.DESCRIPTION, FieldNames.DESCRIPTION);
            validateSecure(vaultDTO.getDescription(), FieldNames.DESCRIPTION);
        }
    }

    /**
     * Validate a vault request DTO specifically for updates
     * 
     * @param requestDTO - The encrypted update request DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateVaultUpdateRequest(VaultRequestDTO requestDTO) throws ValidationException {
        validateNotNull(requestDTO, FieldNames.VAULT_UPDATE);

        // For updates, at least one field should be provided
        boolean hasUpdateFields = requestDTO.getEncryptedName() != null || requestDTO.getEncryptedDescription() != null
                || requestDTO.getIcon() != null;

        if (!hasUpdateFields) {
            throwValidationException(ValidationErrors.UPDATE_AT_LEAST_ONE);
        }

        // If any encrypted field is provided, the helper AES key is required
        boolean hasEncryptedFields = requestDTO.getEncryptedName() != null
                || requestDTO.getEncryptedDescription() != null;

        if (hasEncryptedFields && requestDTO.getHelperAesKey() == null) {
            throwValidationException(ValidationErrors.ENCRYPTION_KEY_REQUIRED);
        }
    }
}