package com.lockbox.exception;

import org.springframework.http.HttpStatus;

public class ExceptionBuilder {

    private String message;
    private HttpStatus status;
    private String entityType;

    private ExceptionBuilder() {
        this.status = HttpStatus.INTERNAL_SERVER_ERROR;
        this.entityType = "Generic";
    }

    public static ExceptionBuilder create() {
        return new ExceptionBuilder();
    }

    public ExceptionBuilder setMessage(String message) {
        this.message = message;
        return this;
    }

    public ExceptionBuilder setStatus(HttpStatus status) {
        this.status = status;
        return this;
    }

    public ExceptionBuilder setEntityType(String entityType) {
        this.entityType = entityType;
        return this;
    }

    public void throwCustomException() {
        throw new CustomException(message, status);
    }

    public void throwValidationException() {
        throw new ValidationException(entityType, message);
    }

    public void throwBadRequestException() {
        this.status = HttpStatus.BAD_REQUEST;
        throwCustomException();
    }

    public void throwUnauthorizedException() {
        this.status = HttpStatus.UNAUTHORIZED;
        throwCustomException();
    }

    public void throwForbiddenException() {
        this.status = HttpStatus.FORBIDDEN;
        throwCustomException();
    }

    public void throwNotFoundException() {
        this.status = HttpStatus.NOT_FOUND;
        throwCustomException();
    }

    public void throwInternalServerErrorException() {
        this.status = HttpStatus.INTERNAL_SERVER_ERROR;
        throwCustomException();
    }
}