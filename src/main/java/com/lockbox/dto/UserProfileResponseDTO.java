package com.lockbox.dto;

public class UserProfileResponseDTO {
    private UserProfileDTO encryptedUserProfileData;

    private EncryptedDataAesCbcDTO encryptedUserPublicKey;

    private EncryptedDataAesCbcDTO encryptedUserPrivateKey;

    private String helperAuthenticateAesKey;

    public UserProfileDTO getEncryptedUserProfileData() {
        return encryptedUserProfileData;
    }

    public void setEncryptedUserProfileData(UserProfileDTO encryptedUserProfileData) {
        this.encryptedUserProfileData = encryptedUserProfileData;
    }

    public EncryptedDataAesCbcDTO getEncryptedUserPublicKey() {
        return encryptedUserPublicKey;
    }

    public void setEncryptedUserPublicKey(EncryptedDataAesCbcDTO encryptedUserPublicKey) {
        this.encryptedUserPublicKey = encryptedUserPublicKey;
    }

    public EncryptedDataAesCbcDTO getEncryptedUserPrivateKey() {
        return encryptedUserPrivateKey;
    }

    public void setEncryptedUserPrivateKey(EncryptedDataAesCbcDTO encryptedUserPrivateKey) {
        this.encryptedUserPrivateKey = encryptedUserPrivateKey;
    }

    public String getHelperAuthenticateAesKey() {
        return helperAuthenticateAesKey;
    }

    public void setHelperAuthenticateAesKey(String helperAuthenticateAesKey) {
        this.helperAuthenticateAesKey = helperAuthenticateAesKey;
    }
}
