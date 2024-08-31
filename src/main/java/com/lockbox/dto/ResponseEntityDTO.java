package com.lockbox.dto;

import java.time.LocalDateTime;

public class ResponseEntityDTO<T> {

    private T item;
    private String error;
    private LocalDateTime timestamp;

    public ResponseEntityDTO() {
        this.timestamp = LocalDateTime.now();
    }

    public ResponseEntityDTO(T item) {
        this();
        this.item = item;
    }

    public ResponseEntityDTO(String error) {
        this();
        this.error = error;
    }

    public T getItem() {
        return item;
    }

    public void setItem(T item) {
        this.item = item;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }
}
