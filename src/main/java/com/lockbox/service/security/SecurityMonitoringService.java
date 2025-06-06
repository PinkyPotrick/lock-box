package com.lockbox.service.security;

import java.util.Map;

/**
 * Service interface for security monitoring. Handles detection of security-related events
 * and triggers appropriate notifications for relevant security events.
 */
public interface SecurityMonitoringService {

    /**
     * Monitor failed login attempts for a user. If too many failed attempts are detected,
     * triggers a security notification.
     * 
     * @param userId    - The ID of the user
     * @param ipAddress - The IP address used for the login attempt
     * @return boolean - true if security alert was generated, false otherwise
     */
    boolean monitorFailedLoginAttempts(String userId, String ipAddress);

    /**
     * Monitor for new device or location logins for a user.
     * 
     * @param userId    - The ID of the user
     * @param ipAddress - The IP address used for the login
     * @param userAgent - The user agent string from the request
     * @return boolean - true if it was a new device/location and notification was created, false otherwise
     */
    boolean monitorNewDeviceLogin(String userId, String ipAddress, String userAgent);

    /**
     * Monitor for suspicious user activity such as unusual login times or locations.
     * 
     * @param userId    - The ID of the user
     * @param ipAddress - The IP address used
     * @param userAgent - The user agent string from the request
     * @param metadata  - Additional metadata about the activity
     * @return boolean - true if suspicious activity was detected and notification was created, false otherwise
     */
    boolean monitorSuspiciousActivity(String userId, String ipAddress, String userAgent, Map<String, Object> metadata);

    /**
     * Monitor for multiple password or recovery phrase change attempts in a short period.
     * 
     * @param userId - The ID of the user
     * @return boolean - true if suspicious activity was detected and notification was created, false otherwise
     */
    boolean monitorCredentialChanges(String userId);
}
