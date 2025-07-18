package com.lockbox.dto.credential;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class CredentialRequestDTO {

    private String vaultId;
    private String domainId;
    private EncryptedDataAesCbcDTO encryptedUsername;
    private EncryptedDataAesCbcDTO encryptedEmail;
    private EncryptedDataAesCbcDTO encryptedPassword;
    private EncryptedDataAesCbcDTO encryptedNotes;
    private EncryptedDataAesCbcDTO encryptedCategory;
    private EncryptedDataAesCbcDTO encryptedFavorite;
    private String helperAesKey;

    public CredentialRequestDTO() {
    }

    public String getVaultId() {
        return vaultId;
    }

    public void setVaultId(String vaultId) {
        this.vaultId = vaultId;
    }

    public String getDomainId() {
        return domainId;
    }

    public void setDomainId(String domainId) {
        this.domainId = domainId;
    }

    public EncryptedDataAesCbcDTO getEncryptedUsername() {
        return encryptedUsername;
    }

    public void setEncryptedUsername(EncryptedDataAesCbcDTO encryptedUsername) {
        this.encryptedUsername = encryptedUsername;
    }

    public EncryptedDataAesCbcDTO getEncryptedEmail() {
        return encryptedEmail;
    }

    public void setEncryptedEmail(EncryptedDataAesCbcDTO encryptedEmail) {
        this.encryptedEmail = encryptedEmail;
    }

    public EncryptedDataAesCbcDTO getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(EncryptedDataAesCbcDTO encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public EncryptedDataAesCbcDTO getEncryptedNotes() {
        return encryptedNotes;
    }

    public void setEncryptedNotes(EncryptedDataAesCbcDTO encryptedNotes) {
        this.encryptedNotes = encryptedNotes;
    }

    public EncryptedDataAesCbcDTO getEncryptedCategory() {
        return encryptedCategory;
    }

    public void setEncryptedCategory(EncryptedDataAesCbcDTO encryptedCategory) {
        this.encryptedCategory = encryptedCategory;
    }

    public EncryptedDataAesCbcDTO getEncryptedFavorite() {
        return encryptedFavorite;
    }

    public void setEncryptedFavorite(EncryptedDataAesCbcDTO encryptedFavorite) {
        this.encryptedFavorite = encryptedFavorite;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}