package com.lockbox.dto.credential;

import java.util.List;

public class CredentialListResponseDTO {

    private List<CredentialResponseDTO> credentials;
    private int totalCount;
    private String vaultName; // TODO maybe encrypt this field too

    public CredentialListResponseDTO() {
    }

    public CredentialListResponseDTO(List<CredentialResponseDTO> credentials, int totalCount) {
        this.credentials = credentials;
        this.totalCount = totalCount;
    }

    public CredentialListResponseDTO(List<CredentialResponseDTO> credentials, int totalCount, String vaultName) {
        this.credentials = credentials;
        this.totalCount = totalCount;
        this.vaultName = vaultName;
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

    public String getVaultName() {
        return vaultName;
    }

    public void setVaultName(String vaultName) {
        this.vaultName = vaultName;
    }
}