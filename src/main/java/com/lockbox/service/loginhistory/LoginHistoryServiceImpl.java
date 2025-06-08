package com.lockbox.service.loginhistory;

import java.time.LocalDateTime;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lockbox.model.LoginHistory;
import com.lockbox.repository.LoginHistoryRepository;
import com.lockbox.utils.AppConstants.SecurityMonitoring;

/**
 * Implementation of the {@link LoginHistoryService} interface. Provides functionality for recording and managing login
 * history.
 */
@Service
public class LoginHistoryServiceImpl implements LoginHistoryService {

    private final Logger logger = LoggerFactory.getLogger(LoginHistoryServiceImpl.class);

    @Autowired
    private LoginHistoryRepository loginHistoryRepository;

    @Autowired
    private LoginHistoryServerEncryptionService loginHistoryServerEncryptionService;

    /**
     * Records a successful login attempt by creating a new LoginHistory entity with success flag set to true,
     * encrypting sensitive data, and saving it to the database.
     * 
     * @param userId    - The ID of the user who logged in
     * @param ipAddress - The IP address from which the login attempt was made
     * @param userAgent - The user agent string from the login request
     * @throws Exception If encryption or database operation fails
     */
    @Override
    @Transactional
    public void recordSuccessfulLogin(String userId, String ipAddress, String userAgent) throws Exception {
        try {
            LocalDateTime now = LocalDateTime.now();

            // Create login history entry
            LoginHistory loginHistory = new LoginHistory(userId, now, ipAddress, userAgent);

            // Encrypt sensitive data
            LoginHistory encryptedLoginHistory = loginHistoryServerEncryptionService.encryptServerData(loginHistory);

            // Save to database
            loginHistoryRepository.save(encryptedLoginHistory);

            logger.info("Recorded successful login for user: {}", userId);
        } catch (Exception e) {
            logger.error("Error recording successful login: {}", e.getMessage());
            // Don't throw exception here to prevent disrupting the login process
        }
    }

    /**
     * Records a failed login attempt by creating a new {@link LoginHistory} entity with success flag set to false,
     * encrypting sensitive data, and saving it to the database.
     * 
     * @param userId        - The ID of the user who attempted to log in
     * @param ipAddress     - The IP address from which the login attempt was made
     * @param userAgent     - The user agent string from the login request
     * @param failureReason - The reason why the login attempt failed
     * @throws Exception If encryption or database operation fails
     */
    @Override
    @Transactional
    public void recordFailedLogin(String userId, String ipAddress, String userAgent, String failureReason)
            throws Exception {
        try {
            LocalDateTime now = LocalDateTime.now();

            // Create login history entry
            LoginHistory loginHistory = new LoginHistory(userId, now, ipAddress, userAgent, false, failureReason);

            // Encrypt sensitive data
            LoginHistory encryptedLoginHistory = loginHistoryServerEncryptionService.encryptServerData(loginHistory);

            // Save to database
            loginHistoryRepository.save(encryptedLoginHistory);

            logger.info("Recorded failed login for user: {}, reason: {}", userId, failureReason);
        } catch (Exception e) {
            logger.error("Error recording failed login: {}", e.getMessage());
            // Don't throw exception here to prevent disrupting the login process
        }
    }

    /**
     * Calculates the login success rate for a user based on their login history.
     * 
     * @param userId - The ID of the user
     * @return Login success rate as a percentage (0-100)
     * @throws Exception If there is an error retrieving login history
     */
    @Override
    public double getLoginSuccessRate(String userId) throws Exception {
        try {
            int totalCount = loginHistoryRepository.countByUserId(userId);

            if (totalCount == 0) {
                return 0.0;
            }

            int successCount = loginHistoryRepository.countByUserIdAndSuccess(userId, true);
            return (double) successCount / totalCount * 100.0;
        } catch (Exception e) {
            logger.error("Error calculating login success rate: {}", e.getMessage());
            throw new Exception("Failed to calculate login success rate", e);
        }
    }

    /**
     * Clears login history entries that are older than the specified date.
     * 
     * @param userId - The ID of the user whose login history should be cleared
     * @param before - The cutoff date; entries older than this will be deleted
     * @return The number of records deleted
     * @throws Exception If deletion fails
     */
    @Override
    @Transactional
    public int clearOldLoginHistory(String userId, LocalDateTime before) throws Exception {
        try {
            List<LoginHistory> oldEntries = loginHistoryRepository
                    .findByLoginTimestampBetweenAndUserIdOrderByLoginTimestampDesc(LocalDateTime.MIN, before, userId);

            int count = oldEntries.size();

            loginHistoryRepository.deleteAll(oldEntries);

            logger.info("Deleted {} old login history records for user: {}", count, userId);
            return count;
        } catch (Exception e) {
            logger.error("Error clearing old login history for user {}: {}", userId, e.getMessage());
            throw new Exception("Failed to clear old login history", e);
        }
    }

    /**
     * Checks if the combination of IP address and user agent is new for this user.
     * 
     * @param userId    - The user ID
     * @param ipAddress - The IP address
     * @param userAgent - The user agent string
     * @return boolean - true if this is a new device/location, false otherwise
     */
    @Override
    public boolean isNewDeviceOrLocation(String userId, String ipAddress, String userAgent) {
        try {
            // Get limited number of recent successful logins for this user
            LocalDateTime lookbackTime = LocalDateTime.now().minusDays(SecurityMonitoring.LOOKBACK_DAYS);
            List<LoginHistory> successfulLogins = loginHistoryRepository
                    .findByUserIdAndSuccessAndTimestampAfterOrderByTimestampDesc(userId, true, lookbackTime);

            if (successfulLogins.isEmpty()) {
                logger.info("New device/location for user {} (first login)", userId);
                return true;
            }

            String currentDeviceSignature = ipAddress + "|" + userAgent;

            for (LoginHistory login : successfulLogins) {
                try {
                    LoginHistory decryptedLogin = loginHistoryServerEncryptionService.decryptServerData(login);

                    String historicalDeviceSignature = decryptedLogin.getIpAddress() + "|"
                            + decryptedLogin.getUserAgent();

                    if (currentDeviceSignature.equals(historicalDeviceSignature)) {
                        logger.debug("Found existing device/location for user {}", userId);
                        return false;
                    }
                } catch (Exception e) {
                    logger.warn("Could not decrypt login history record {}: {}", login.getId(), e.getMessage());
                }
            }

            logger.info("New device/location detected for user {}", userId);
            return true;

        } catch (Exception e) {
            logger.error("Error checking for new device/location: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Counts the number of failed login attempts for a user within the last hour.
     * 
     * @param userId - The user ID
     * @return int - The count of recent failed attempts
     */
    @Override
    public int countRecentFailedAttempts(String userId) {
        // Look for failed logins in the last hour
        LocalDateTime oneHourAgo = LocalDateTime.now().minusHours(1);

        return loginHistoryRepository.countByUserIdAndSuccessAndTimestampAfter(userId, false, oneHourAgo);
    }
}