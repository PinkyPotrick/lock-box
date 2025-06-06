package com.lockbox.model;

public enum NotificationType {
    // Security notifications
    LOGIN_NEW_LOCATION, LOGIN_FAILED_ATTEMPTS, PASSWORD_CHANGED, ACCOUNT_LOCKED, SUSPICIOUS_ACTIVITY, SECURITY_ALERT,

    // System notifications
    ACCOUNT, CONTENT,

    // Vault notifications
    VAULT_DELETED,

    // Credential notifications
    CREDENTIAL_UPDATED, CREDENTIAL_DELETED
}