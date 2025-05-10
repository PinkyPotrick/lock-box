package com.lockbox.dto.credential;

import java.util.List;

public class CredentialListResponseDTO {

    private List<CredentialResponseDTO> credentials;

    private long totalCount;

    public CredentialListResponseDTO(List<CredentialResponseDTO> credentials, long totalCount) {
        this.credentials = credentials;
        this.totalCount = totalCount;
    }

    public List<CredentialResponseDTO> getCredentials() {
        return credentials;
    }

    public void setCredentials(List<CredentialResponseDTO> credentials) {
        this.credentials = credentials;
    }

    public long getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(long totalCount) {
        this.totalCount = totalCount;
    }
}