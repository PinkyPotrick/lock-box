package com.lockbox.exception;

import org.springframework.http.HttpStatus;

/**
 * Custom exception with HTTP status.
 */
public class CustomException extends RuntimeException {

    private static final long serialVersionUID = 1L;
    private final HttpStatus status;

    /**
     * Creates a new {@link CustomException} with message and status.
     *
     * @param message - The error message
     * @param status  - The HTTP status code
     */
    public CustomException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    /**
     * Creates a new {@link CustomException} with message, cause, and status.
     *
     * @param message - The error message
     * @param cause   - The cause of this exception
     * @param status  - The HTTP status code
     */
    public CustomException(String message, Throwable cause, HttpStatus status) {
        super(message, cause);
        this.status = status;
    }

    /**
     * Get the HTTP status code.
     * 
     * @return The HTTP status
     */
    public HttpStatus getStatus() {
        return status;
    }
}