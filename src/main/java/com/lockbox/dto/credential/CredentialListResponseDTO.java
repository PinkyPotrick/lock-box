package com.lockbox.dto.credential;

import java.util.List;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class CredentialListResponseDTO {

    private List<CredentialResponseDTO> credentials;
    private int totalCount;
    private EncryptedDataAesCbcDTO encryptedVaultName;
    private String helperVaultNameAesKey;

    public CredentialListResponseDTO() {
    }

    public CredentialListResponseDTO(List<CredentialResponseDTO> credentials, int totalCount, 
            EncryptedDataAesCbcDTO encryptedVaultName, String helperVaultNameAesKey) {
        this.credentials = credentials;
        this.totalCount = totalCount;
        this.encryptedVaultName = encryptedVaultName;
        this.helperVaultNameAesKey = helperVaultNameAesKey;
    }

    public List<CredentialResponseDTO> getCredentials() {
        return credentials;
    }

    public void setCredentials(List<CredentialResponseDTO> credentials) {
        this.credentials = credentials;
    }

    public int getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(int totalCount) {
        this.totalCount = totalCount;
    }

    public EncryptedDataAesCbcDTO getEncryptedVaultName() {
        return encryptedVaultName;
    }

    public void setEncryptedVaultName(EncryptedDataAesCbcDTO encryptedVaultName) {
        this.encryptedVaultName = encryptedVaultName;
    }

    public String getHelperVaultNameAesKey() {
        return helperVaultNameAesKey;
    }

    public void setHelperVaultNameAesKey(String helperVaultNameAesKey) {
        this.helperVaultNameAesKey = helperVaultNameAesKey;
    }
}