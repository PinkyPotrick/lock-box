package com.lockbox.dto.totp;

public class TotpVerifyRequestDTO {
    private String code;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}