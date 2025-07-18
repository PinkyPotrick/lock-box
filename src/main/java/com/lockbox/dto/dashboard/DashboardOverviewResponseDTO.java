package com.lockbox.dto.dashboard;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class DashboardOverviewResponseDTO {

    private EncryptedDataAesCbcDTO encryptedOverview;
    private String helperAesKey;

    public DashboardOverviewResponseDTO() {
    }

    public EncryptedDataAesCbcDTO getEncryptedOverview() {
        return encryptedOverview;
    }

    public void setEncryptedOverview(EncryptedDataAesCbcDTO encryptedOverview) {
        this.encryptedOverview = encryptedOverview;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}