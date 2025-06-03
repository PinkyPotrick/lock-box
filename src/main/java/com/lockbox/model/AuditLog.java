package com.lockbox.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_logs")
public class AuditLog extends BaseEntity {

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 50)
    private String actionType;

    @Column(length = 255)
    private String resourceId;

    @Column(length = 1024)
    private String resourceName;

    @Column(name = "client_info", length = 255)
    private String clientInfo;

    @Column(name = "ip_address", length = 50)
    private String ipAddress;

    @Column(name = "action_status", nullable = false, length = 20)
    private String actionStatus;

    @Column(name = "failure_reason", length = 1024)
    private String failureReason;

    @Column(name = "additional_info", length = 2048)
    private String additionalInfo;

    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    @Column(nullable = false, length = 344)
    private String aesKey;

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getActionType() {
        return actionType;
    }

    public void setActionType(String actionType) {
        this.actionType = actionType;
    }

    public String getResourceId() {
        return resourceId;
    }

    public void setResourceId(String resourceId) {
        this.resourceId = resourceId;
    }

    public String getResourceName() {
        return resourceName;
    }

    public void setResourceName(String resourceName) {
        this.resourceName = resourceName;
    }

    public String getClientInfo() {
        return clientInfo;
    }

    public void setClientInfo(String clientInfo) {
        this.clientInfo = clientInfo;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getActionStatus() {
        return actionStatus;
    }

    public void setActionStatus(String actionStatus) {
        this.actionStatus = actionStatus;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }

    public String getAdditionalInfo() {
        return additionalInfo;
    }

    public void setAdditionalInfo(String additionalInfo) {
        this.additionalInfo = additionalInfo;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getAesKey() {
        return aesKey;
    }

    public void setAesKey(String aesKey) {
        this.aesKey = aesKey;
    }
}