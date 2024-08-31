package com.lockbox.utils;

import com.lockbox.dto.ResponseEntityDTO;
import java.time.LocalDateTime;

public class ResponseEntityBuilder<T> {

    private T data;
    private String error;
    private LocalDateTime timestamp;

    public ResponseEntityBuilder() {
        this.timestamp = LocalDateTime.now();
    }

    public ResponseEntityBuilder<T> setData(T data) {
        this.data = data;
        return this;
    }

    public ResponseEntityBuilder<T> setError(String error) {
        this.error = error;
        return this;
    }

    public ResponseEntityBuilder<T> setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
        return this;
    }

    public ResponseEntityDTO<T> build() {
        ResponseEntityDTO<T> responseEntityDTO = new ResponseEntityDTO<>();
        responseEntityDTO.setItem(this.data);
        responseEntityDTO.setError(this.error);
        responseEntityDTO.setTimestamp(this.timestamp);
        return responseEntityDTO;
    }
}
