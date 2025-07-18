package com.lockbox.validators;

import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.lockbox.exception.ValidationException;
import com.lockbox.utils.AppConstants;

/**
 * Base validator class that provides common validation methods with XSS protection. This class is meant to be extended
 * by specific entity validators.
 */
public abstract class BaseValidator {

    protected final Logger logger;
    protected final String entityType;

    // XSS protection patterns
    private static final Pattern XSS_SCRIPT_PATTERN = Pattern.compile(
            "(?i)<script[^>]*>.*?</script>|javascript:|on\\w+\\s*=|<\\s*iframe|<\\s*object|<\\s*embed",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Pattern HTML_TAG_PATTERN = Pattern.compile("<[^>]+>", Pattern.CASE_INSENSITIVE);

    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(?i)(\\b(select|insert|update|delete|drop|create|alter|exec|union|script)\\b)|(-{2,})|(/\\*.*?\\*/)",
            Pattern.CASE_INSENSITIVE);

    protected BaseValidator(String entityType) {
        this.entityType = entityType;
        this.logger = LoggerFactory.getLogger(this.getClass());
    }

    /**
     * Throw a validation exception for this entity type.
     * 
     * @param message - The validation error message
     * @throws ValidationException with the entity type and message
     */
    protected void throwValidationException(String message) {
        logger.error("Validation error for {}: {}", entityType, message);
        throw new ValidationException(entityType, message);
    }

    /**
     * Validate that a field is not null or empty.
     * 
     * @param value        - Field value to check
     * @param fieldName    - Name of the field for the error message
     * @param errorMessage - Custom error message (optional)
     * @throws ValidationException if the field is null or empty
     */
    protected void validateRequired(String value, String fieldName, String... errorMessage) {
        if (value == null || value.trim().isEmpty()) {
            String message = errorMessage.length > 0 ? errorMessage[0]
                    : AppConstants.ValidationErrors.REQUIRED_FIELD.replace("{0}", fieldName);
            throwValidationException(message);
        }
    }

    /**
     * Validate that an object is not null.
     * 
     * @param value        - Object to check
     * @param objectName   - Name of the object for the error message
     * @param errorMessage - Custom error message (optional)
     * @throws ValidationException if the object is null
     */
    protected void validateNotNull(Object value, String objectName, String... errorMessage) {
        if (value == null) {
            String message = errorMessage.length > 0 ? errorMessage[0]
                    : AppConstants.ValidationErrors.NULL_REQUEST.replace("{0}", objectName);
            throwValidationException(message);
        }
    }

    /**
     * Validate that a string does not exceed the maximum length.
     * 
     * @param value     - String to check
     * @param maxLength - Maximum allowed length
     * @param fieldName - Name of the field for the error message
     * @throws ValidationException if the string exceeds max length
     */
    protected void validateMaxLength(String value, int maxLength, String fieldName) {
        if (value != null && value.length() > maxLength) {
            throwValidationException(AppConstants.ValidationErrors.MAX_LENGTH.replace("{0}", fieldName).replace("{1}",
                    String.valueOf(maxLength)));
        }
    }

    /**
     * Validate that a string matches a specific regex pattern.
     * 
     * @param value     - String to check
     * @param pattern   - Regex pattern to match
     * @param fieldName - Name of the field for the error message
     * @throws ValidationException if the string does not match the pattern
     */
    protected void validateXSSSafe(String value, String fieldName) {
        if (value == null)
            return;

        if (XSS_SCRIPT_PATTERN.matcher(value).find()) {
            logger.warn("XSS attempt detected in field {}: {}", fieldName, value);
            throwValidationException("Invalid characters detected in " + fieldName);
        }

        if (HTML_TAG_PATTERN.matcher(value).find()) {
            logger.warn("HTML tags detected in field {}: {}", fieldName, value);
            throwValidationException("HTML tags are not allowed in " + fieldName);
        }
    }

    /**
     * Validate that a string is safe from SQL injection attempts.
     * 
     * @param value     - String to check
     * @param fieldName - Name of the field for the error message
     * @throws ValidationException if the string contains SQL injection patterns
     */
    protected void validateSQLSafe(String value, String fieldName) {
        if (value == null)
            return;

        if (SQL_INJECTION_PATTERN.matcher(value).find()) {
            logger.warn("SQL injection attempt detected in field {}: {}", fieldName, value);
            throwValidationException("Invalid characters detected in " + fieldName);
        }
    }

    /**
     * Validate a string for both XSS and SQL injection safety.
     * 
     * @param value     - String to validate
     * @param fieldName - Name of the field for the error message
     * @throws ValidationException if the string is unsafe
     */
    protected void validateSecure(String value, String fieldName) {
        validateXSSSafe(value, fieldName);
        validateSQLSafe(value, fieldName);
    }

    /**
     * Check if a string is not null and not empty after trimming.
     * 
     * @param value - String to check
     * @return true if the string has content, false otherwise
     */
    protected boolean hasContent(String value) {
        return value != null && !value.trim().isEmpty();
    }

    /**
     * Validate an ID field (required and not empty).
     * 
     * @param id        - ID value to validate
     * @param fieldName - Name of the ID field
     * @throws ValidationException if the ID is invalid
     */
    protected void validateId(String id, String fieldName) {
        validateRequired(id, fieldName);
        // UUIDs should only contain alphanumeric and hyphens
        if (!Pattern.matches("^[a-fA-F0-9-]+$", id)) {
            throwValidationException("Invalid " + fieldName + " format");
        }
    }
}