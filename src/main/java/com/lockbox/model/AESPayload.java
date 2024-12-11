package com.lockbox.model;

public class AESPayload {
    private String encryptedData;
    private String iv;
    private String hmac;

    public AESPayload(String encryptedData, String iv, String hmac) {
        this.encryptedData = encryptedData;
        this.iv = iv;
        this.hmac = hmac;
    }

    public String getEncryptedData() {
        return encryptedData;
    }

    public void setEncryptedData(String encryptedData) {
        this.encryptedData = encryptedData;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getHmac() {
        return hmac;
    }

    public void setHmac(String hmac) {
        this.hmac = hmac;
    }
}
