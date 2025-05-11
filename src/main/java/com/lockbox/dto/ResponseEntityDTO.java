package com.lockbox.dto;

import java.time.LocalDateTime;

public class ResponseEntityDTO<T> {

    private T item;
    private String message;
    private boolean success;
    private int statusCode;
    private String errorType;
    private LocalDateTime timestamp;

    public ResponseEntityDTO() {
        this.timestamp = LocalDateTime.now();
    }

    public ResponseEntityDTO(T item) {
        this();
        this.item = item;
    }

    public ResponseEntityDTO(String message) {
        this();
        this.message = message;
    }

    public T getItem() {
        return item;
    }

    public void setItem(T item) {
        this.item = item;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getErrorType() {
        return errorType;
    }

    public void setErrorType(String errorType) {
        this.errorType = errorType;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}