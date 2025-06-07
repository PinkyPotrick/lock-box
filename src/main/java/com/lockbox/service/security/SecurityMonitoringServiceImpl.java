package com.lockbox.service.security;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.ActionType;
import com.lockbox.model.LogLevel;
import com.lockbox.model.OperationType;
import com.lockbox.repository.AuditLogRepository;
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
    private static final int CREDENTIAL_CHANGES_THRESHOLD = 3;
    private static final int CREDENTIAL_CHANGES_HOURS = 24;

    @Autowired
    private LoginHistoryService loginHistoryService;

    @Autowired
    private NotificationCreationService notificationCreationService;

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private AuditLogRepository auditLogRepository;

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
            int recentFailedAttempts = loginHistoryService.countRecentFailedAttempts(userId);

            if (recentFailedAttempts >= AppConstants.FAILED_LOGIN_ATTEMPTS_THRESHOLD) {
                logger.info("Multiple failed login attempts detected for user {}: {} recent attempts from IP {}",
                        userId, recentFailedAttempts, ipAddress);

                notificationCreationService.createFailedLoginAttemptsNotification(userId, recentFailedAttempts,
                        ipAddress);

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
            boolean isNewDevice = loginHistoryService.isNewDeviceOrLocation(userId, ipAddress, userAgent);

            if (isNewDevice) {
                logger.info("Login from new device/location detected for user {}: IP={}, UserAgent={}", userId,
                        ipAddress, userAgent);

                notificationCreationService.createNewLoginNotification(userId, ipAddress);

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
            // Enhanced implementation with actual detection logic
            boolean isSuspicious = false;
            StringBuilder reasonBuilder = new StringBuilder();

            // Check 1: Unusual login time (if user typically doesn't log in at this hour)
            LocalDateTime currentTime = LocalDateTime.now();
            int currentHour = currentTime.getHour();

            // Analyze if this hour is unusual for this user based on login history
            boolean isUnusualTime = isUnusualLoginTime(userId, currentHour);
            if (isUnusualTime) {
                isSuspicious = true;
                reasonBuilder.append("Unusual login time detected. ");
                logger.warn("Unusual login time detected for user {} at hour {}", userId, currentHour);
            }

            // Check 2: Rapid geographical location change (if supported)
            boolean isRapidLocationChange = checkRapidLocationChange(userId, ipAddress);
            if (isRapidLocationChange) {
                isSuspicious = true;
                reasonBuilder.append("Rapid geographical location change detected. ");
                logger.warn("Suspicious rapid location change for user {}, new IP: {}", userId, ipAddress);
            }

            // Check 3: Access from high-risk location
            boolean isHighRiskLocation = isHighRiskLocation(ipAddress);
            if (isHighRiskLocation) {
                isSuspicious = true;
                reasonBuilder.append("Login from high-risk location. ");
                logger.warn("Login from high-risk location for user {}, IP: {}", userId, ipAddress);
            }

            if (isSuspicious) {
                notificationCreationService.createSuspiciousActivityNotification(userId, ipAddress);

                auditLogService.logUserAction(userId, ActionType.SUSPICIOUS_ACTIVITY_DETECTED, OperationType.READ,
                        LogLevel.WARNING, null, "Security Monitoring", ActionStatus.WARNING,
                        "Suspicious account activity",
                        "Suspicious activity detected: " + reasonBuilder.toString() + " IP: " + ipAddress);

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
            // Implement actual detection logic for frequent credential changes
            LocalDateTime checkFrom = LocalDateTime.now().minus(CREDENTIAL_CHANGES_HOURS, ChronoUnit.HOURS);

            // Count credential-related changes in the audit log
            int changeCount = countRecentCredentialChanges(userId, checkFrom);

            boolean isSuspicious = changeCount >= CREDENTIAL_CHANGES_THRESHOLD;

            if (isSuspicious) {
                logger.warn("Frequent credential changes detected for user {}: {} changes in {}h", userId, changeCount,
                        CREDENTIAL_CHANGES_HOURS);

                notificationCreationService.createFrequentChangesNotification(userId);

                auditLogService.logUserAction(userId, ActionType.FREQUENT_PASSWORD_CHANGES, OperationType.UPDATE,
                        LogLevel.WARNING, null, "Security Monitoring", ActionStatus.WARNING,
                        "Frequent credential changes", String.format("User made %d credential changes within %d hours",
                                changeCount, CREDENTIAL_CHANGES_HOURS));

                return true;
            }
        } catch (Exception e) {
            logger.error("Error monitoring credential changes: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Determines if login time is unusual for this user based on their history
     */
    private boolean isUnusualLoginTime(String userId, int currentHour) {
        // This would analyze historic login patterns
        // Simple implementation: If user typically logs in during business hours (9-17)
        // and current login is outside of that, flag it
        return (currentHour < 6 || currentHour > 22); // Flag logins between 10 PM and 6 AM
    }

    /**
     * Check if user has recently logged in from a very different geographic location
     */
    private boolean checkRapidLocationChange(String userId, String ipAddress) {
        try {
            // Get user's most recent successful login
            // Get geo location for current and previous IP
            // Calculate distance and time between logins
            // If distance is large and time is short, flag it

            // Stub implementation - would be replaced with actual geo-location logic
            return false;
        } catch (Exception e) {
            logger.error("Error checking rapid location change: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Check if IP address is from a known high-risk location
     */
    private boolean isHighRiskLocation(String ipAddress) {
        // Would use a geo-IP database to check against known high-risk regions
        // Stub implementation
        return false;
    }

    /**
     * Count recent credential change operations in audit logs
     */
    private int countRecentCredentialChanges(String userId, LocalDateTime since) {
        try {
            List<ActionType> credentialChangeActions = List.of(ActionType.PASSWORD_CHANGE, ActionType.CREDENTIAL_UPDATE,
                    ActionType.PASSWORD_RESET_COMPLETE);

            return auditLogRepository.countByUserIdAndActionTypeInAndTimestampAfter(userId, credentialChangeActions,
                    since);
        } catch (Exception e) {
            logger.error("Error counting recent credential changes: {}", e.getMessage());
            return 0;
        }
    }
}
