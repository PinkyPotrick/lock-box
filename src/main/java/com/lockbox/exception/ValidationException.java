package com.lockbox.exception;

/**
 * Generic validation exception that can be used for any entity.
 */
public class ValidationException extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private final String entityType;

    /**
     * Constructs a ValidationException with a specific entity type and message.
     * 
     * @param entityType Type of entity that failed validation (e.g., "Credential", "Vault", "Domain")
     * @param message    Description of the validation error
     */
    public ValidationException(String entityType, String message) {
        super(message);
        this.entityType = entityType;
    }

    /**
     * Constructs a ValidationException with a specific entity type, message, and cause.
     * 
     * @param entityType Type of entity that failed validation
     * @param message    Description of the validation error
     * @param cause      The underlying cause of the validation failure
     */
    public ValidationException(String entityType, String message, Throwable cause) {
        super(message, cause);
        this.entityType = entityType;
    }

    /**
     * Get the type of entity that failed validation.
     * 
     * @return Entity type name
     */
    public String getEntityType() {
        return entityType;
    }
}