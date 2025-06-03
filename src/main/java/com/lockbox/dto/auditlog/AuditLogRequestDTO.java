package com.lockbox.dto.auditlog;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;

public class AuditLogRequestDTO {

    private String userId;
    private String actionType;
    private String actionStatus;
    private String ipAddress;
    private EncryptedDataAesCbcDTO encryptedResourceId;
    private EncryptedDataAesCbcDTO encryptedResourceName;
    private EncryptedDataAesCbcDTO encryptedClientInfo;
    private EncryptedDataAesCbcDTO encryptedFailureReason;
    private EncryptedDataAesCbcDTO encryptedAdditionalInfo;
    private String helperAesKey;

    public AuditLogRequestDTO() {
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getActionType() {
        return actionType;
    }

    public void setActionType(String actionType) {
        this.actionType = actionType;
    }

    public String getActionStatus() {
        return actionStatus;
    }

    public void setActionStatus(String actionStatus) {
        this.actionStatus = actionStatus;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public EncryptedDataAesCbcDTO getEncryptedResourceId() {
        return encryptedResourceId;
    }

    public void setEncryptedResourceId(EncryptedDataAesCbcDTO encryptedResourceId) {
        this.encryptedResourceId = encryptedResourceId;
    }

    public EncryptedDataAesCbcDTO getEncryptedResourceName() {
        return encryptedResourceName;
    }

    public void setEncryptedResourceName(EncryptedDataAesCbcDTO encryptedResourceName) {
        this.encryptedResourceName = encryptedResourceName;
    }

    public EncryptedDataAesCbcDTO getEncryptedClientInfo() {
        return encryptedClientInfo;
    }

    public void setEncryptedClientInfo(EncryptedDataAesCbcDTO encryptedClientInfo) {
        this.encryptedClientInfo = encryptedClientInfo;
    }

    public EncryptedDataAesCbcDTO getEncryptedFailureReason() {
        return encryptedFailureReason;
    }

    public void setEncryptedFailureReason(EncryptedDataAesCbcDTO encryptedFailureReason) {
        this.encryptedFailureReason = encryptedFailureReason;
    }

    public EncryptedDataAesCbcDTO getEncryptedAdditionalInfo() {
        return encryptedAdditionalInfo;
    }

    public void setEncryptedAdditionalInfo(EncryptedDataAesCbcDTO encryptedAdditionalInfo) {
        this.encryptedAdditionalInfo = encryptedAdditionalInfo;
    }

    public String getHelperAesKey() {
        return helperAesKey;
    }

    public void setHelperAesKey(String helperAesKey) {
        this.helperAesKey = helperAesKey;
    }
}