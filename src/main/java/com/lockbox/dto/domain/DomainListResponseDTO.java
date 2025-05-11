package com.lockbox.dto.domain;

import java.util.List;

public class DomainListResponseDTO {

    private List<DomainResponseDTO> domains;
    private int totalCount;

    public DomainListResponseDTO() {
    }

    public DomainListResponseDTO(List<DomainResponseDTO> domains, int totalCount) {
        this.domains = domains;
        this.totalCount = totalCount;
    }

    public List<DomainResponseDTO> getDomains() {
        return domains;
    }

    public void setDomains(List<DomainResponseDTO> domains) {
        this.domains = domains;
    }

    public int getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(int totalCount) {
        this.totalCount = totalCount;
    }
}