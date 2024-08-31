package com.lockbox.utils;

import com.lockbox.model.CustomException;

import org.springframework.http.HttpStatus;

public class ExceptionBuilder {
    private String message;

    private ExceptionBuilder() {}

    public static ExceptionBuilder create() {
        return new ExceptionBuilder();
    }

    public ExceptionBuilder setMessage(String message) {
        this.message = message;
        return this;
    }

    public void throwBadRequestException() {
        throw new CustomException(message, HttpStatus.BAD_REQUEST);
    }

    public void throwInternalServerErrorException() {
        throw new CustomException(message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
