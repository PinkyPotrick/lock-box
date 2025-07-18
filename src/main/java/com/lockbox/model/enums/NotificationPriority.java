package com.lockbox.model.enums;
/**
 * Enum representing the priority levels for notifications.
 * Each priority level has a different auto-expiration policy:
 * - LOW: Auto-expire after 30 days
 * - MEDIUM: Auto-expire after 60 days
 * - HIGH: Auto-expire after 90 days
 * - CRITICAL: Never auto-expire
 */
public enum NotificationPriority {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}