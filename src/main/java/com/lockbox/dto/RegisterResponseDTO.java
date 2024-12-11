package com.lockbox.dto;

public class RegisterResponseDTO {
    private UserProfileDTO encryptedUserProfileData;
    
    private EncryptedDataAesCbcDTO encryptedSessionToken;
    
    private String helperAesKey;

    public UserProfileDTO getEncryptedUserProfileData() {
        return encryptedUserProfileData;
    }

    public void setEncryptedUserProfileData(UserProfileDTO encryptedUserProfileData) {
        this.encryptedUserProfileData = encryptedUserProfileData;
    }

    public EncryptedDataAesCbcDTO getEncryptedSessionToken() {
        return encryptedSessionToken;
    }

    public void setEncryptedSessionToken(EncryptedDataAesCbcDTO encryptedSessionToken) {
        this.encryptedSessionToken = encryptedSessionToken;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}
