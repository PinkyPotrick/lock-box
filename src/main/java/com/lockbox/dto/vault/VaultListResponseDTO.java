package com.lockbox.dto.vault;

import java.util.List;

public class VaultListResponseDTO {

    private List<VaultResponseDTO> vaults;
    private int totalCount;

    public VaultListResponseDTO() {
    }

    public VaultListResponseDTO(List<VaultResponseDTO> vaults, int totalCount) {
        this.vaults = vaults;
        this.totalCount = totalCount;
    }

    public List<VaultResponseDTO> getVaults() {
        return vaults;
    }

    public void setVaults(List<VaultResponseDTO> vaults) {
        this.vaults = vaults;
    }

    public int getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(int totalCount) {
        this.totalCount = totalCount;
    }
}