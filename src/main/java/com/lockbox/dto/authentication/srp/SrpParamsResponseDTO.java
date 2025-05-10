package com.lockbox.dto.authentication.srp;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

/**
 * The encrypted SRP parameters sent to frontend.
 */
public class SrpParamsResponseDTO {
    private EncryptedDataAesCbcDTO encryptedServerPublicValueB;

    private String helperSrpParamsAesKey;

    private String salt;

    public EncryptedDataAesCbcDTO getEncryptedServerPublicValueB() {
        return encryptedServerPublicValueB;
    }

    public void setEncryptedServerPublicValueB(EncryptedDataAesCbcDTO encryptedServerPublicValueB) {
        this.encryptedServerPublicValueB = encryptedServerPublicValueB;
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
}
