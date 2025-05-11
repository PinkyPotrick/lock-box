package com.lockbox.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.exception.CustomException;
import com.lockbox.exception.ValidationException;

public class ResponseEntityBuilder<T> {

    private static final Logger logger = LoggerFactory.getLogger(ResponseEntityBuilder.class);

    private T data;
    private String message;
    private boolean success = true;
    private int statusCode = 200;

    public ResponseEntityBuilder<T> setData(T data) {
        this.data = data;
        return this;
    }

    public ResponseEntityBuilder<T> setMessage(String message) {
        this.message = message;
        return this;
    }

    public ResponseEntityBuilder<T> setSuccess(boolean success) {
        this.success = success;
        return this;
    }

    public ResponseEntityBuilder<T> setStatusCode(int statusCode) {
        this.statusCode = statusCode;
        return this;
    }

    public ResponseEntityDTO<T> build() {
        ResponseEntityDTO<T> responseEntityDTO = new ResponseEntityDTO<>();
        responseEntityDTO.setItem(data);
        responseEntityDTO.setMessage(message != null ? message : "Operation completed successfully");
        responseEntityDTO.setSuccess(success);
        responseEntityDTO.setStatusCode(statusCode);
        return responseEntityDTO;
    }

    public static <E> ResponseEntityDTO<E> handleErrorDTO(Exception exception, String context) {
        // Log the exception with context
        logger.error("{}: {}", context, exception.getMessage(), exception);

        // Create response DTO
        ResponseEntityDTO<E> responseDTO = new ResponseEntityDTO<>();
        responseDTO.setItem(null);
        responseDTO.setSuccess(false);

        int statusCode;
        String errorType;

        // Determine status code and error type based on exception
        if (exception instanceof ValidationException) {
            ValidationException validationEx = (ValidationException) exception;
            statusCode = HttpStatus.BAD_REQUEST.value();
            responseDTO.setMessage(validationEx.getMessage());
            errorType = validationEx.getEntityType() + " Validation Error";
        } else if (exception instanceof CustomException) {
            CustomException customEx = (CustomException) exception;
            statusCode = customEx.getStatus().value();
            responseDTO.setMessage(customEx.getMessage());
            errorType = "Application Error";
        } else {
            statusCode = HttpStatus.INTERNAL_SERVER_ERROR.value();
            responseDTO.setMessage(context + ": " + exception.getMessage());
            errorType = "Server Error";
        }

        responseDTO.setStatusCode(statusCode);
        responseDTO.setErrorType(errorType);

        return responseDTO;
    }
}