package com.lockbox.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "login_history")
public class LoginHistory extends BaseEntity {

    @Column(name = "user_id", nullable = false)
    private String userId;

    @Column(name = "login_timestamp", nullable = false)
    private LocalDateTime loginTimestamp;

    @Column(name = "date", nullable = false)
    private String date;

    // IP address could be sensitive, so encrypt it
    @Column(name = "ip_address")
    private String ipAddress;

    // User agent could contain identifiable information
    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "success", nullable = false)
    private boolean success;

    @Column(name = "failure_reason")
    private String failureReason;

    @Column(name = "timestamp")
    private LocalDateTime timestamp;

    @Column(nullable = false, length = 344)
    private String aesKey;

    public LoginHistory() {
    }

    public LoginHistory(String userId, LocalDateTime loginTimestamp, String ipAddress, String userAgent) {
        this(userId, loginTimestamp, ipAddress, userAgent, true, null);
    }

    public LoginHistory(String userId, LocalDateTime loginTimestamp, String ipAddress, String userAgent,
            boolean success, String failureReason) {
        this.userId = userId;
        this.loginTimestamp = loginTimestamp;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.success = success;
        this.failureReason = failureReason;
        this.date = loginTimestamp.format(DateTimeFormatter.ISO_LOCAL_DATE);
        this.timestamp = loginTimestamp;
    }

    @PrePersist
    public void prePersist() {
        if (this.loginTimestamp == null) {
            this.loginTimestamp = LocalDateTime.now();
        }

        if (this.date == null) {
            this.date = this.loginTimestamp.format(DateTimeFormatter.ISO_LOCAL_DATE);
        }

        if (this.timestamp == null) {
            this.timestamp = this.loginTimestamp;
        }
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public LocalDateTime getLoginTimestamp() {
        return loginTimestamp;
    }

    public void setLoginTimestamp(LocalDateTime loginTimestamp) {
        this.loginTimestamp = loginTimestamp;
    }

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
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