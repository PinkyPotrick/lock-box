package com.lockbox.service.security;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.ActionType;
import com.lockbox.model.LogLevel;
import com.lockbox.model.OperationType;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.loginhistory.LoginHistoryService;
import com.lockbox.service.notification.NotificationCreationService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.ActionStatus;

/**
 * Implementation of {@link SecurityMonitoringService} interface. Monitors security events and creates appropriate
 * notifications for users.
 */
@Service
public class SecurityMonitoringServiceImpl implements SecurityMonitoringService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityMonitoringServiceImpl.class);

    @Autowired
    private LoginHistoryService loginHistoryService;

    @Autowired
    private NotificationCreationService notificationCreationService;

    @Autowired
    private AuditLogService auditLogService;

    /**
     * Monitor failed login attempts for a user. If too many failed attempts are detected, triggers a security
     * notification.
     * 
     * @param userId    - The ID of the user
     * @param ipAddress - The IP address used for the login attempt
     * @return boolean - true if security alert was generated, false otherwise
     */
    @Override
    public boolean monitorFailedLoginAttempts(String userId, String ipAddress) {
        try {
            // Check for multiple failed login attempts
            int recentFailedAttempts = loginHistoryService.countRecentFailedAttempts(userId);

            // If failed attempts exceed threshold, create notification
            if (recentFailedAttempts >= AppConstants.FAILED_LOGIN_ATTEMPTS_THRESHOLD) {
                logger.info("Multiple failed login attempts detected for user {}: {} recent attempts from IP {}",
                        userId, recentFailedAttempts, ipAddress);

                // Create notification for user
                notificationCreationService.createFailedLoginAttemptsNotification(userId, recentFailedAttempts,
                        ipAddress);

                // Log this security event
                auditLogService.logUserAction(userId, ActionType.LOGIN_FAILED, OperationType.READ, LogLevel.WARNING,
                        null, "Authentication System", ActionStatus.FAILURE, "Multiple failed login attempts",
                        "Multiple failed login attempts detected. Count: " + recentFailedAttempts + ", IP: "
                                + ipAddress);

                return true;
            }
        } catch (Exception e) {
            logger.error("Error monitoring failed login attempts: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Monitor for new device or location logins for a user.
     * 
     * @param userId    - The ID of the user
     * @param ipAddress - The IP address used for the login
     * @param userAgent - The user agent string from the request
     * @return boolean - true if it was a new device/location and notification was created, false otherwise
     */
    @Override
    public boolean monitorNewDeviceLogin(String userId, String ipAddress, String userAgent) {
        try {
            // Check if this is a new device/location
            boolean isNewDevice = loginHistoryService.isNewDeviceOrLocation(userId, ipAddress, userAgent);

            if (isNewDevice) {
                logger.info("Login from new device/location detected for user {}: IP={}, UserAgent={}", userId,
                        ipAddress, userAgent);

                // Create notification for user
                notificationCreationService.createNewLoginNotification(userId, ipAddress);

                // Log this security event
                auditLogService.logUserAction(userId, ActionType.LOGIN_NEW_DEVICE, OperationType.READ, LogLevel.INFO,
                        null, "Authentication System", ActionStatus.SUCCESS, "Login from new device/location",
                        "Login detected from new device or location. IP: " + ipAddress);

                return true;
            }
        } catch (Exception e) {
            logger.error("Error monitoring new device login: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Monitor for suspicious user activity such as unusual login times or locations.
     * 
     * @param userId    - The ID of the user
     * @param ipAddress - The IP address used
     * @param userAgent - The user agent string from the request
     * @param metadata  - Additional metadata about the activity
     * @return boolean - true if suspicious activity was detected and notification was created, false otherwise
     */
    @Override
    public boolean monitorSuspiciousActivity(String userId, String ipAddress, String userAgent,
            Map<String, Object> metadata) {
        try {
            // Implementation could include:
            // 1. Checking for logins at unusual hours
            // 2. Detecting logins from high-risk countries
            // 3. Detecting rapid geographical location changes
            // 4. Analyzing access patterns for anomalies

            // For now, just log that this would be implemented with more advanced algorithms
            logger.info("Suspicious activity monitoring would analyze user {} activity from IP={}, UserAgent={}",
                    userId, ipAddress, userAgent);

            // This would be expanded with actual detection logic
            boolean isSuspicious = false;

            if (isSuspicious) {
                // Create notification for user
                notificationCreationService.createSuspiciousActivityNotification(userId, ipAddress);

                // Log this security event
                auditLogService.logUserAction(userId, ActionType.SUSPICIOUS_ACTIVITY_DETECTED, OperationType.READ,
                        LogLevel.WARNING, null, "Security Monitoring", ActionStatus.WARNING,
                        "Suspicious account activity", "Suspicious activity detected for account. IP: " + ipAddress);

                return true;
            }
        } catch (Exception e) {
            logger.error("Error monitoring suspicious activity: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Monitor for multiple password or recovery phrase change attempts in a short period.
     * 
     * @param userId - The ID of the user
     * @return boolean - true if suspicious activity was detected and notification was created, false otherwise
     */
    @Override
    public boolean monitorCredentialChanges(String userId) {
        try {
            // This would check audit logs for frequent credential changes
            // Implementation would track how many credential changes occurred in a specific period

            // Log that this would be implemented with more detailed tracking
            logger.info("Credential change monitoring would check frequency of changes for user {}", userId);

            // This would be expanded with actual detection logic
            boolean isSuspicious = false;

            if (isSuspicious) {
                // Create notification for user
                notificationCreationService.createFrequentChangesNotification(userId);

                // Log this security event
                auditLogService.logUserAction(userId, ActionType.FREQUENT_PASSWORD_CHANGES, OperationType.UPDATE,
                        LogLevel.WARNING, null, "Security Monitoring", ActionStatus.WARNING,
                        "Frequent credential changes", "Multiple credential changes detected within a short period");

                return true;
            }
        } catch (Exception e) {
            logger.error("Error monitoring credential changes: {}", e.getMessage());
        }
        return false;
    }
}
