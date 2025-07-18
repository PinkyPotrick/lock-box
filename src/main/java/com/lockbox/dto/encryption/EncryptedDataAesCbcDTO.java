package com.lockbox.dto.encryption;

public class EncryptedDataAesCbcDTO {
    private String encryptedDataBase64;

    private String ivBase64;

    private String hmacBase64;

    public String getEncryptedDataBase64() {
        return encryptedDataBase64;
    }

    public void setEncryptedDataBase64(String encryptedDataBase64) {
        this.encryptedDataBase64 = encryptedDataBase64;
    }

    public String getIvBase64() {
        return ivBase64;
    }

    public void setIvBase64(String ivBase64) {
        this.ivBase64 = ivBase64;
    }

    public String getHmacBase64() {
        return hmacBase64;
    }

    public void setHmacBase64(String hmacBase64) {
        this.hmacBase64 = hmacBase64;
    }
}
