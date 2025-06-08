package com.lockbox.service.security;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lockbox.model.LoginHistory;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.repository.AuditLogRepository;
import com.lockbox.repository.LoginHistoryRepository;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.loginhistory.LoginHistoryServerEncryptionService;
import com.lockbox.service.loginhistory.LoginHistoryService;
import com.lockbox.service.notification.NotificationCreationService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.ActionStatus;
import com.lockbox.utils.AppConstants.SecurityMonitoring;

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

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private LoginHistoryRepository loginHistoryRepository;

    @Autowired
    private LoginHistoryServerEncryptionService loginHistoryServerEncryptionService;

    @Autowired
    private GeoLocationService geoLocationService;

    @Autowired
    private ObjectMapper objectMapper;

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
            boolean isSuspicious = false;
            StringBuilder reasonBuilder = new StringBuilder();
            Map<String, Object> allMetadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();

            // Check 1: Unusual login time (if user typically doesn't log in at this hour)
            LocalDateTime currentTime = LocalDateTime.now();
            int currentHour = currentTime.getHour();

            boolean isUnusualTime = isUnusualLoginTime(userId, currentHour);
            if (isUnusualTime) {
                isSuspicious = true;
                reasonBuilder.append("Unusual login time detected. ");
                allMetadata.put("unusualTime", true);
                logger.warn("Unusual login time detected for user {} at hour {}", userId, currentHour);
            }

            // Check 2: Rapid geographical location change
            boolean isRapidLocationChange = checkRapidLocationChange(userId, ipAddress);
            if (isRapidLocationChange) {
                isSuspicious = true;
                reasonBuilder.append("Rapid geographical location change detected. ");
                allMetadata.put("rapidLocationChange", true);
                logger.warn("Suspicious rapid location change for user {}, new IP: {}", userId, ipAddress);
            }

            // Check 3: Access from high-risk location
            boolean isHighRiskLocation = isHighRiskLocation(ipAddress);
            if (isHighRiskLocation) {
                isSuspicious = true;
                reasonBuilder.append("Login from high-risk location. ");
                allMetadata.put("highRiskLocation", true);
                logger.warn("Login from high-risk location for user {}, IP: {}", userId, ipAddress);
            }

            if (isSuspicious) {
                // Create a detailed notification with all detected issues
                String notificationDetails = ipAddress;
                if (!reasonBuilder.toString().isEmpty()) {
                    notificationDetails += " (" + reasonBuilder.toString().trim() + ")";
                }

                String metadataJson = objectMapper.writeValueAsString(allMetadata);

                notificationCreationService.createSuspiciousActivityNotification(userId, notificationDetails,
                        metadataJson);

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
            LocalDateTime checkFrom = LocalDateTime.now().minus(SecurityMonitoring.CREDENTIAL_CHANGES_HOURS,
                    ChronoUnit.HOURS);

            // Count credential-related changes in the audit log
            int changeCount = countRecentCredentialChanges(userId, checkFrom);

            boolean isSuspicious = changeCount >= SecurityMonitoring.CREDENTIAL_CHANGES_THRESHOLD;

            if (isSuspicious) {
                logger.warn("Frequent credential changes detected for user {}: {} changes in {}h", userId, changeCount,
                        SecurityMonitoring.CREDENTIAL_CHANGES_HOURS);

                notificationCreationService.createFrequentChangesNotification(userId);

                auditLogService.logUserAction(userId, ActionType.FREQUENT_PASSWORD_CHANGES, OperationType.UPDATE,
                        LogLevel.WARNING, null, "Security Monitoring", ActionStatus.WARNING,
                        "Frequent credential changes", String.format("User made %d credential changes within %d hours",
                                changeCount, SecurityMonitoring.CREDENTIAL_CHANGES_HOURS));

                return true;
            }
        } catch (Exception e) {
            logger.error("Error monitoring credential changes: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Determines if login time is unusual for this user based on their history. This method adapts to the user's actual
     * login patterns over time.
     * 
     * @param userId      - The user ID
     * @param currentHour - The current hour of login (0-23)
     * @return boolean - true if the login time is unusual for this user
     */
    private boolean isUnusualLoginTime(String userId, int currentHour) {
        try {

            // Get user's recent login history
            LocalDateTime since = LocalDateTime.now().minusDays(SecurityMonitoring.LOOKBACK_DAYS);
            List<LoginHistory> recentLogins = loginHistoryRepository.findSuccessfulLoginsByUserIdSince(userId, since);

            // If insufficient history, use default business hours logic
            if (recentLogins.size() < SecurityMonitoring.MIN_LOGIN_HISTORY) {
                logger.debug("Insufficient login history for user {}, using default hours check", userId);
                return currentHour < SecurityMonitoring.DEFAULT_MORNING_HOUR
                        || currentHour > SecurityMonitoring.DEFAULT_EVENING_HOUR;
            }

            // Count logins per hour
            int[] hourCounts = new int[24];
            for (LoginHistory login : recentLogins) {
                int hour = login.getLoginTimestamp().getHour();
                hourCounts[hour]++;
            }

            // Calculate frequency of logins at current hour
            double frequencyAtCurrentHour = (double) hourCounts[currentHour] / recentLogins.size();

            // Log for debugging
            logger.debug("User {} login frequency at hour {}: {:.2f}% (threshold: {:.2f}%)", userId, currentHour,
                    frequencyAtCurrentHour * 100, SecurityMonitoring.UNUSUAL_THRESHOLD * 100);

            // Check if current hour is unusual (occurs significantly less often than average)
            boolean isUnusual = frequencyAtCurrentHour < SecurityMonitoring.UNUSUAL_THRESHOLD;

            // If it's the first login at this hour, but we have history, it's definitely unusual
            if (hourCounts[currentHour] == 0 && recentLogins.size() >= 10) {
                isUnusual = true;
            }

            // Additional check: is this hour a complete outlier compared to adjacent hours?
            // (This helps detect cases where someone might be logging in at 3 AM when they
            // normally log in during daytime)
            int prevHour = (currentHour + 23) % 24; // Handle hour 0 properly
            int nextHour = (currentHour + 1) % 24;

            if (hourCounts[currentHour] == 0 && hourCounts[prevHour] == 0 && hourCounts[nextHour] == 0) {
                // If there are no logins in the current hour or adjacent hours, that's unusual
                isUnusual = true;
            }

            return isUnusual;

        } catch (Exception e) {
            logger.error("Error analyzing login time patterns for user {}: {}", userId, e.getMessage());
            return currentHour < SecurityMonitoring.DEFAULT_MORNING_HOUR
                    || currentHour > SecurityMonitoring.DEFAULT_EVENING_HOUR;
        }
    }

    /**
     * Check if user has recently logged in from a very different geographic location Uses existing LoginHistory data to
     * determine if there's a suspicious location change
     */
    private boolean checkRapidLocationChange(String userId, String ipAddress) {
        try {
            // Get recent successful logins for this user
            LocalDateTime timeThreshold = LocalDateTime.now().minusHours(SecurityMonitoring.TIME_THRESHOLD_HOURS);
            List<LoginHistory> recentLogins = loginHistoryRepository
                    .findByUserIdAndSuccessAndTimestampAfterOrderByTimestampDesc(userId, true, timeThreshold);

            // If this is their first login or no recent logins, not suspicious
            if (recentLogins.isEmpty()) {
                return false;
            }

            // Get the most recent login (excluding current one)
            // We need to decrypt the IP address first
            LoginHistory lastLogin = recentLogins.get(0);
            LoginHistory decryptedLastLogin = loginHistoryServerEncryptionService.decryptServerData(lastLogin);
            String lastIpAddress = decryptedLastLogin.getIpAddress();

            // If it's the same IP, obviously not suspicious
            if (ipAddress.equals(lastIpAddress)) {
                return false;
            }

            // Get coordinates for both IPs
            Optional<double[]> currentCoords = geoLocationService.getCoordinates(ipAddress);
            Optional<double[]> lastCoords = geoLocationService.getCoordinates(lastIpAddress);

            // If we don't have coordinates for either IP, fall back to country comparison
            if (currentCoords.isEmpty() || lastCoords.isEmpty()) {
                Optional<String> currentCountry = geoLocationService.getCountryCode(ipAddress);
                Optional<String> lastCountry = geoLocationService.getCountryCode(lastIpAddress);

                if (currentCountry.isPresent() && lastCountry.isPresent()) {
                    return !currentCountry.get().equals(lastCountry.get());
                }
                return false;
            }

            // Calculate the distance between the two locations
            double[] current = currentCoords.get();
            double[] last = lastCoords.get();
            double distance = geoLocationService.calculateDistance(last[0], last[1], current[0], current[1]);

            // Log the calculated distance
            logger.debug("Distance between current IP {} and previous IP {} for user {}: {} km", ipAddress,
                    lastIpAddress, userId, distance);

            // If the distance is large and time is short, flag it as suspicious
            LocalDateTime lastLoginTime = lastLogin.getLoginTimestamp();
            LocalDateTime now = LocalDateTime.now();
            long hoursBetween = ChronoUnit.HOURS.between(lastLoginTime, now);

            // The shorter the time between logins with large distance, the more suspicious it is
            boolean isRapidTravel = distance > SecurityMonitoring.SUSPICIOUS_DISTANCE_KM
                    && hoursBetween < SecurityMonitoring.TIME_THRESHOLD_HOURS;

            if (isRapidTravel) {
                logger.warn("Detected suspicious rapid location change for user {}. Distance: {} km in {} hours",
                        userId, distance, hoursBetween);
            }

            return isRapidTravel;
        } catch (Exception e) {
            logger.error("Error checking rapid location change: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Check if IP address is from a known high-risk location Uses GeoLocationService to determine if an IP is from a
     * high-risk country or region
     */
    private boolean isHighRiskLocation(String ipAddress) {
        try {
            // Check if this IP is from a high-risk country
            boolean isHighRiskCountry = geoLocationService.isHighRiskCountry(ipAddress);

            if (isHighRiskCountry) {
                Optional<String> country = geoLocationService.getCountryCode(ipAddress);
                logger.warn("Login detected from high-risk country: {}, IP: {}", country.orElse("unknown"), ipAddress);
                return true;
            }

            // Additional checks could be implemented here:
            // 1. Check if IP is from a known proxy/VPN/Tor exit node
            // 2. Check if IP is on security blocklists
            // 3. Check if IP has been involved in previous security incidents

            return false;
        } catch (Exception e) {
            logger.error("Error checking if location is high risk: {}", e.getMessage(), e);
            return false;
        }
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
