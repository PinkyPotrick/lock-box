package com.lockbox.dto.userprofile;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class UserProfileResponseDTO {
    private EncryptedDataAesCbcDTO encryptedUserProfile;
    private String helperAesKey;
    private boolean totpEnabled;
    
    public EncryptedDataAesCbcDTO getEncryptedUserProfile() {
        return encryptedUserProfile;
    }

    public void setEncryptedUserProfile(EncryptedDataAesCbcDTO encryptedUserProfile) {
        this.encryptedUserProfile = encryptedUserProfile;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
    
    public boolean isTotpEnabled() {
        return totpEnabled;
    }
    
    public void setTotpEnabled(boolean totpEnabled) {
        this.totpEnabled = totpEnabled;
    }
}
