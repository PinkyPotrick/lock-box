package com.lockbox.dto.totp;

public class TotpVerifyRequestDTO {
    private String code;
    private String operation;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }
}