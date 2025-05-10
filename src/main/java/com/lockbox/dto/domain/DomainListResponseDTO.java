package com.lockbox.dto.domain;

import java.util.List;

public class DomainListResponseDTO {

    private List<DomainResponseDTO> domains;

    private long totalCount;

    public DomainListResponseDTO(List<DomainResponseDTO> domains, long totalCount) {
        this.domains = domains;
        this.totalCount = totalCount;
    }

    public List<DomainResponseDTO> getDomains() {
        return domains;
    }

    public void setDomains(List<DomainResponseDTO> domains) {
        this.domains = domains;
    }

    public long getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(long totalCount) {
        this.totalCount = totalCount;
    }
}