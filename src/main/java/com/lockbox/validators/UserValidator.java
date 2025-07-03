package com.lockbox.validators;

import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.lockbox.dto.authentication.registration.UserRegistrationDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.repository.UserRepository;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.FieldNames;
import com.lockbox.utils.AppConstants.ValidationErrors;
import com.lockbox.utils.AppConstants.ValidationPatterns;
import com.lockbox.utils.EncryptionUtils;

@Component
public class UserValidator extends BaseValidator {

    @Autowired
    private UserRepository userRepository;

    public UserValidator() {
        super(AppConstants.EntityTypes.USER);
    }

    /**
     * Validate the user registration data.
     * 
     * @param userRegistrationDTO - The user registration data to validate
     * @throws ValidationException If validation fails
     */
    public void validate(UserRegistrationDTO userRegistrationDTO) throws ValidationException {
        validateNotNull(userRegistrationDTO, FieldNames.USER_REGISTRATION);

        String derivedUsername = userRegistrationDTO.getDerivedUsername();
        try {
            String username = EncryptionUtils.decryptUsername(derivedUsername, userRegistrationDTO.getDerivedKey());
            validateUsernameFormat(username);
            validateEmailFormat(userRegistrationDTO.getEmail());
            validateSalt(userRegistrationDTO.getSalt());
            validateVerifier(userRegistrationDTO.getClientVerifier());

            // Check existence only after all other validations passed
            // This prevents information leakage about which specific field exists
            validateUserDoesNotExist(derivedUsername, userRegistrationDTO.getEmail());
        } catch (Exception e) {
            // Convert any standard exceptions to ValidationException
            if (e instanceof ValidationException) {
                throw (ValidationException) e;
            }
            throwValidationException(e.getMessage());
        }
    }

    /**
     * Validate username format only.
     * 
     * @param username - The decrypted username
     * @throws ValidationException If validation fails
     */
    private void validateUsernameFormat(String username) throws ValidationException {
        validateRequired(username, FieldNames.USERNAME);
        validateSecure(username, FieldNames.USERNAME);

        if (!Pattern.matches(ValidationPatterns.USERNAME_PATTERN, username)) {
            throwValidationException(ValidationErrors.INVALID_USERNAME_FORMAT);
        }
    }

    /**
     * Validate email format only.
     * 
     * @param email - The email to validate
     * @throws ValidationException If validation fails
     */
    private void validateEmailFormat(String email) throws ValidationException {
        validateRequired(email, FieldNames.EMAIL);
        validateSecure(email, FieldNames.EMAIL);

        if (!Pattern.matches(ValidationPatterns.EMAIL_PATTERN, email)) {
            throwValidationException(ValidationErrors.INVALID_EMAIL_FORMAT);
        }
    }

    /**
     * Check if the user already exists by username or email. Uses a generic error message to prevent user enumeration.
     * 
     * @param derivedUsername - The derived username
     * @param email           - The email
     * @throws ValidationException if user exists
     */
    private void validateUserDoesNotExist(String derivedUsername, String email) throws ValidationException {
        try {
            boolean usernameExists = userRepository.findByUsername(derivedUsername) != null;
            boolean emailExists = userRepository.findByEmail(email) != null;

            if (usernameExists || emailExists) {
                // Generic error that doesn't reveal which field caused the conflict
                throwValidationException(ValidationErrors.USER_ALREADY_EXISTS);
            }
        } catch (Exception e) {
            // Log the actual error but don't expose it to the client
            logger.error("Database error while checking user existence: {}", e.getMessage());
            throwValidationException(ValidationErrors.REGISTRATION_ERROR);
        }
    }

    /**
     * Validate that the salt is not empty.
     * 
     * @param salt - The salt to validate
     * @throws ValidationException If validation fails
     */
    private void validateSalt(String salt) throws ValidationException {
        validateRequired(salt, FieldNames.SALT, ValidationErrors.SALT_REQUIRED);
        validateSecure(salt, FieldNames.SALT);
    }

    /**
     * Validate that the verifier is not empty.
     * 
     * @param verifier - The verifier to validate
     * @throws ValidationException If validation fails
     */
    private void validateVerifier(String verifier) throws ValidationException {
        validateRequired(verifier, FieldNames.VERIFIER, ValidationErrors.VERIFIER_REQUIRED);
        validateSecure(verifier, FieldNames.VERIFIER);
    }
}