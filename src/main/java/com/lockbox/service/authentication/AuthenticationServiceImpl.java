package com.lockbox.service.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.lockbox.model.ActionType;
import com.lockbox.model.LogLevel;
import com.lockbox.model.OperationType;
import com.lockbox.service.SessionKeyStoreService;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.loginhistory.LoginHistoryService;
import com.lockbox.service.notification.NotificationCreationService;
import com.lockbox.service.security.SecurityMonitoringService;
import com.lockbox.service.token.TokenBlacklistService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.ActionStatus;
import com.lockbox.utils.RequestUtils;
import com.lockbox.utils.SecurityUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private SessionKeyStoreService sessionKeyStore;

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private LoginHistoryService loginHistoryService;

    @Autowired
    private SecurityUtils securityUtils;

    @Autowired
    private AuditLogService auditLogService;    @Autowired
    private NotificationCreationService notificationCreationService;
    
    @Autowired
    private SecurityMonitoringService securityMonitoringService;

    private final Logger logger = LoggerFactory.getLogger(AuthenticationServiceImpl.class);

    @Override
    public void logout() {
        try {
            // Extract token using SecurityUtils - completely request-independent
            String token = securityUtils.getCurrentToken();

            // Get user info
            String userId = securityUtils.getCurrentUserId();
            logger.info("User logged out: {}", userId);

            // Add audit logging for logout
            try {
                auditLogService.logUserAction(userId, ActionType.USER_LOGOUT, OperationType.READ, LogLevel.INFO, null,
                        "Authentication System", ActionStatus.SUCCESS, null, "User logged out");
            } catch (Exception e) {
                logger.error("Failed to create audit log for logout: {}", e.getMessage());
            }

            // Add the token to blacklist to prevent reuse
            tokenBlacklistService.blacklistToken(token);

            // Clear encryption keys from session
            sessionKeyStore.clearUserKeys();

            // Invalidate the session from the current request context
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder
                    .getRequestAttributes();
            if (attributes != null) {
                HttpSession session = attributes.getRequest().getSession(false);
                if (session != null) {
                    session.invalidate();
                }
            }
        } catch (Exception e) {
            logger.warn("Error during logout: {}", e.getMessage());
        }
    }    /**
     * Processes a successful authentication and records it in the login history.
     * 
     * @param userId The ID of the authenticated user
     * @throws Exception If recording fails
     */
    @Override
    public void recordSuccessfulAuthentication(String userId) throws Exception {
        // Get IP address and user agent
        String ipAddress = RequestUtils.getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        // Record successful login
        loginHistoryService.recordSuccessfulLogin(userId, ipAddress, userAgent);

        // Add audit logging
        try {
            auditLogService.logUserAction(userId, ActionType.USER_LOGIN, OperationType.READ, LogLevel.INFO, null,
                    "Authentication System", ActionStatus.SUCCESS, null, "User login successful from IP: " + ipAddress);
        } catch (Exception e) {
            logger.error("Failed to create audit log for login: {}", e.getMessage());
            // Don't rethrow - authentication still succeeded
        }
        
        // Check if this is a login from a new device/location
        try {
            securityMonitoringService.monitorNewDeviceLogin(userId, ipAddress, userAgent);
        } catch (Exception e) {
            logger.error("Failed during security monitoring for new device login: {}", e.getMessage());
        }
    }

    /**
     * Processes a failed authentication and records it in the login history.
     * 
     * @param userId The attempted user ID
     * @param reason The reason for the authentication failure
     * @throws Exception If recording fails
     */
    @Override
    public void recordFailedAuthentication(String userId, String reason) {
        // Get IP address and user agent
        String ipAddress = RequestUtils.getClientIpAddress(request);
        String userAgent = request.getHeader("User-Agent");

        try {
            loginHistoryService.recordFailedLogin(userId, ipAddress, userAgent, reason);

            auditLogService.logUserAction(userId, ActionType.LOGIN_FAILED, OperationType.READ, LogLevel.WARNING, null,
                    "Authentication System", ActionStatus.FAILURE, reason,
                    "Failed login attempt from IP: " + ipAddress);
        } catch (Exception e) {
            logger.error("Failed to create audit log for failed login: {}", e.getMessage());
            // Don't rethrow - the failed authentication is already recorded
        }

        // If threshold reached (e.g., 5 attempts), create notification
        int recentFailedAttempts = getRecentFailedAttempts(userId);
        if (recentFailedAttempts >= 5) {
            try {
                notificationCreationService.createFailedLoginAttemptsNotification(userId, recentFailedAttempts,
                        ipAddress);
            } catch (Exception ex) {
                logger.error("Failed to create login attempt notification: {}", ex.getMessage());
            }
        }

        // If account gets locked due to too many attempts
        if (recentFailedAttempts >= AppConstants.MAX_ATTEMPTS_BEFORE_LOCK) {
            try {
                notificationCreationService.createAccountLockedNotification(userId);
            } catch (Exception ex) {
                logger.error("Failed to create account locked notification: {}", ex.getMessage());
            }
        }
    }

    /**
     * Determines if the current login is from a new device or location by checking the login history.
     * 
     * @param userId    - The ID of the user who is logging in
     * @param ipAddress - The IP address of the current login
     * @return boolean - true if this is a new device or location, false otherwise
     */
    @Override
    public boolean isNewDeviceOrLocation(String userId, String ipAddress) {
        String userAgent = request.getHeader("User-Agent");

        try {
            // Check if this combination of IP and user agent has been used before
            boolean isNewDevice = loginHistoryService.isNewDeviceOrLocation(userId, ipAddress, userAgent);

            if (isNewDevice) {
                logger.info("New device or location detected for user {}: IP={}, UserAgent={}", userId, ipAddress,
                        userAgent);

                // Log this event
                try {
                    auditLogService.logUserAction(userId, ActionType.LOGIN_NEW_DEVICE, OperationType.READ,
                            LogLevel.INFO, null, "Authentication System", ActionStatus.SUCCESS, "New device detected",
                            "Login from new device or location. IP: " + ipAddress);
                } catch (Exception e) {
                    logger.error("Failed to create audit log for new device login: {}", e.getMessage());
                }
            }

            return isNewDevice;
        } catch (Exception e) {
            logger.error("Error checking for new device or location: {}", e.getMessage());
            // In case of error, assume it's not a new device to avoid unnecessary notifications
            return false;
        }
    }

    /**
     * Gets the number of recent failed authentication attempts for a user.
     * 
     * @param userId - The ID of the user
     * @return int - The number of recent failed attempts
     */
    @Override
    public int getRecentFailedAttempts(String userId) {
        try {
            // Use the login history service to count recent failed attempts (e.g., in the last hour)
            return loginHistoryService.countRecentFailedAttempts(userId);
        } catch (Exception e) {
            logger.error("Error counting recent failed attempts: {}", e.getMessage());
            return 0;
        }
    }
}
