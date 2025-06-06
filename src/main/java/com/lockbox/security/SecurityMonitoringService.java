package com.lockbox.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.ActionType;
import com.lockbox.model.LogLevel;
import com.lockbox.model.OperationType;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.notification.NotificationCreationService;

/**
 * Service to monitor security-related events and detect suspicious activities. This service can be used across the
 * application to report unusual behaviors that might indicate security concerns.
 */
@Service
public class SecurityMonitoringService {

    private final Logger logger = LoggerFactory.getLogger(SecurityMonitoringService.class);

    @Autowired
    private NotificationCreationService notificationCreationService;

    @Autowired
    private AuditLogService auditLogService;

    /**
     * Report suspicious activity detected for a user. This will create both an audit log and a high-priority
     * notification for the user.
     * 
     * @param userId      - The ID of the user related to the suspicious activity
     * @param description - Detailed description of the suspicious activity
     * @param ipAddress   - The IP address from which the suspicious activity originated
     */
    public void reportSuspiciousActivity(String userId, String description, String ipAddress) {
        // Log the suspicious activity in system logs
        logger.warn("Suspicious activity detected for user {}: {} from IP {}", userId, description, ipAddress);

        // Create detailed audit log
        try {
            auditLogService.logUserAction(userId, ActionType.SECURITY_WARNING, OperationType.READ, LogLevel.WARNING,
                    null, "Security Monitoring", "WARNING", "Suspicious activity detected",
                    description + " from IP: " + ipAddress);
        } catch (Exception e) {
            logger.error("Failed to create audit log for suspicious activity: {}", e.getMessage(), e);
        }

        // Create notification for the user
        try {
            notificationCreationService.createSuspiciousActivityNotification(userId,
                    description + " (IP: " + ipAddress + ")");
        } catch (Exception e) {
            logger.error("Failed to create suspicious activity notification: {}", e.getMessage(), e);
        }
    }

    /**
     * Report an account lockout event.
     * 
     * @param userId - The ID of the locked account
     * @param reason - The reason for the lockout
     */
    public void reportAccountLockout(String userId, String reason) {
        logger.warn("Account locked for user {}: {}", userId, reason);

        try {
            auditLogService.logUserAction(userId, ActionType.SECURITY_WARNING, OperationType.UPDATE, LogLevel.WARNING,
                    null, "Security Monitoring", "WARNING", "Account locked", reason);
        } catch (Exception e) {
            logger.error("Failed to create audit log for account lockout: {}", e.getMessage(), e);
        }

        try {
            notificationCreationService.createAccountLockedNotification(userId);
        } catch (Exception e) {
            logger.error("Failed to create account lockout notification: {}", e.getMessage(), e);
        }
    }

    /**
     * Report multiple failed login attempts.
     * 
     * @param userId       - The ID of the user whose login attempts failed
     * @param attemptCount - The number of failed attempts
     * @param ipAddress    - The IP address of the last failed attempt
     */
    public void reportFailedLoginAttempts(String userId, int attemptCount, String ipAddress) {
        logger.warn("Multiple failed login attempts ({}) for user {} from IP {}", attemptCount, userId, ipAddress);

        try {
            auditLogService.logUserAction(userId, ActionType.AUTHENTICATION, OperationType.READ, LogLevel.WARNING, null,
                    "Security Monitoring", "WARNING", "Multiple failed login attempts",
                    "Failed attempts: " + attemptCount + ", Last IP: " + ipAddress);
        } catch (Exception e) {
            logger.error("Failed to create audit log for failed login attempts: {}", e.getMessage(), e);
        }

        try {
            notificationCreationService.createFailedLoginAttemptsNotification(userId, attemptCount, ipAddress);
        } catch (Exception e) {
            logger.error("Failed to create failed login attempts notification: {}", e.getMessage(), e);
        }
    }

    /**
     * Report a successful login from a new device or location.
     * 
     * @param userId     - The ID of the user who logged in
     * @param ipAddress  - The IP address of the new login
     * @param deviceInfo - Information about the device used
     */
    public void reportNewDeviceLogin(String userId, String ipAddress, String deviceInfo) {
        logger.info("New device login for user {} from IP {}: {}", userId, ipAddress, deviceInfo);

        try {
            auditLogService.logUserAction(userId, ActionType.AUTHENTICATION, OperationType.READ, LogLevel.INFO, null,
                    "Security Monitoring", "INFO", "Login from new device/location",
                    "IP: " + ipAddress + ", Device: " + deviceInfo);
        } catch (Exception e) {
            logger.error("Failed to create audit log for new device login: {}", e.getMessage(), e);
        }

        try {
            notificationCreationService.createNewLoginNotification(userId, ipAddress);
        } catch (Exception e) {
            logger.error("Failed to create new login notification: {}", e.getMessage(), e);
        }
    }

    /**
     * Check if activity from an IP address is suspicious based on various factors.
     * 
     * @param userId    - The user ID
     * @param ipAddress - The IP address to check
     * @param action    - The action being performed
     * @return boolean - true if the activity is suspicious
     */
    public boolean isActivitySuspicious(String userId, String ipAddress, String action) {
        // This is a placeholder for more sophisticated logic
        // In a real implementation, you might:
        // 1. Check if this IP has been used by this user before
        // 2. Check geolocation of IP against typical usage patterns
        // 3. Check time of day against typical usage patterns
        // 4. Check for known malicious IP addresses
        // 5. Apply machine learning models for anomaly detection

        // For now, implement a simple check - return false to avoid false positives
        return false;
    }
}