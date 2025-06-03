package com.lockbox.dto.auditlog;

import java.time.LocalDateTime;

import com.lockbox.dto.encryption.EncryptedDataAesCbcDTO;
import com.lockbox.model.AuditLog.LogLevel;
import com.lockbox.model.AuditLog.OperationType;

public class AuditLogResponseDTO {

    private String id;
    private String userId;
    private LocalDateTime timestamp;
    private String actionType;
    private OperationType operationType;
    private LogLevel logLevel;
    private String actionStatus;
    private String ipAddress;
    private EncryptedDataAesCbcDTO encryptedResourceId;
    private EncryptedDataAesCbcDTO encryptedResourceName;
    private String clientInfo;
    private String failureReason;
    private EncryptedDataAesCbcDTO encryptedAdditionalInfo;
    private String helperAesKey;

    public AuditLogResponseDTO() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getActionType() {
        return actionType;
    }

    public void setActionType(String actionType) {
        this.actionType = actionType;
    }

    public OperationType getOperationType() {
        return operationType;
    }

    public void setOperationType(OperationType operationType) {
        this.operationType = operationType;
    }

    public LogLevel getLogLevel() {
        return logLevel;
    }

    public void setLogLevel(LogLevel logLevel) {
        this.logLevel = logLevel;
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

    public String getClientInfo() {
        return clientInfo;
    }

    public void setClientInfo(String clientInfo) {
        this.clientInfo = clientInfo;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
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