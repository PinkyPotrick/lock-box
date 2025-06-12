package com.lockbox.dto.authentication.srp;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

/**
 * The encrypted SRP parameters sent to frontend.
 */
public class SrpParamsResponseDTO {
    private EncryptedDataAesCbcDTO encryptedServerPublicValueB;

    private EncryptedDataAesCbcDTO encryptedTotpSessionId;

    private String helperSrpParamsAesKey;

    private String salt;

    private Boolean requiresTotp;

    public EncryptedDataAesCbcDTO getEncryptedServerPublicValueB() {
        return encryptedServerPublicValueB;
    }

    public void setEncryptedServerPublicValueB(EncryptedDataAesCbcDTO encryptedServerPublicValueB) {
        this.encryptedServerPublicValueB = encryptedServerPublicValueB;
    }

    public EncryptedDataAesCbcDTO getEncryptedTotpSessionId() {
        return encryptedTotpSessionId;
    }

    public void setEncryptedTotpSessionId(EncryptedDataAesCbcDTO encryptedTotpSessionId) {
        this.encryptedTotpSessionId = encryptedTotpSessionId;
    }

    public String getHelperSrpParamsAesKey() {
        return helperSrpParamsAesKey;
    }

    public void setHelperSrpParamsAesKey(String helperSrpParamsAesKey) {
        this.helperSrpParamsAesKey = helperSrpParamsAesKey;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public Boolean getRequiresTotp() {
        return requiresTotp;
    }

    public void setRequiresTotp(Boolean requiresTotp) {
        this.requiresTotp = requiresTotp;
    }
}
