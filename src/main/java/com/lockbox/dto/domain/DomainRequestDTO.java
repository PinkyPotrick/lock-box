package com.lockbox.dto.domain;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class DomainRequestDTO {

    private String userId;
    private String logo;
    private EncryptedDataAesCbcDTO encryptedName;
    private EncryptedDataAesCbcDTO encryptedUrl;
    private EncryptedDataAesCbcDTO encryptedNotes;
    private String helperAesKey;

    public DomainRequestDTO() {
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getLogo() {
        return logo;
    }

    public void setLogo(String logo) {
        this.logo = logo;
    }

    public EncryptedDataAesCbcDTO getEncryptedName() {
        return encryptedName;
    }

    public void setEncryptedName(EncryptedDataAesCbcDTO encryptedName) {
        this.encryptedName = encryptedName;
    }

    public EncryptedDataAesCbcDTO getEncryptedUrl() {
        return encryptedUrl;
    }

    public void setEncryptedUrl(EncryptedDataAesCbcDTO encryptedUrl) {
        this.encryptedUrl = encryptedUrl;
    }

    public EncryptedDataAesCbcDTO getEncryptedNotes() {
        return encryptedNotes;
    }

    public void setEncryptedNotes(EncryptedDataAesCbcDTO encryptedNotes) {
        this.encryptedNotes = encryptedNotes;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}