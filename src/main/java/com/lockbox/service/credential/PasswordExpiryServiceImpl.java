package com.lockbox.service.credential;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lockbox.model.Credential;
import com.lockbox.repository.CredentialRepository;
import com.lockbox.service.notification.NotificationCreationService;
import com.lockbox.utils.AppConstants.PasswordExpiry;

/**
 * Implementation of the {@link PasswordExpiryService} that checks for passwords nearing expiration and sends
 * appropriate notifications.
 */
@Service
public class PasswordExpiryServiceImpl implements PasswordExpiryService {

    private final Logger logger = LoggerFactory.getLogger(PasswordExpiryServiceImpl.class);

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private CredentialServerEncryptionService credentialServerEncryptionService;

    @Autowired
    private NotificationCreationService notificationCreationService;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Scheduled task that runs daily to check for passwords nearing expiration and sends appropriate notifications.
     */
    @Scheduled(cron = "0 0 0 * * ?") // Run at midnight every day
    @Transactional(readOnly = true)
    @Override
    public int checkPasswordExpirations() {
        logger.info("Running scheduled password expiration check");

        int notificationsSent = 0;

        try {
            // Get all credentials to check
            List<Credential> allCredentials = credentialRepository.findAll();

            for (Credential encryptedCredential : allCredentials) {
                try {
                    // Decrypt the credential to get meaningful data
                    Credential credential = credentialServerEncryptionService.decryptServerData(encryptedCredential);
                    if (shouldSendNotification(credential)) {
                        sendPasswordExpiryNotification(credential);
                        notificationsSent++;
                    }
                } catch (Exception e) {
                    logger.error("Error processing credential {} for password expiry: {}", encryptedCredential.getId(),
                            e.getMessage());
                }
            }

            logger.info("Password expiration check completed. Sent {} notifications", notificationsSent);
        } catch (Exception e) {
            logger.error("Error running password expiration check: {}", e.getMessage(), e);
        }

        return notificationsSent;
    }

    /**
     * Determine if a notification should be sent for this credential based on its expiration date
     * 
     * @param credential The decrypted credential
     * @return true if notification should be sent, false otherwise
     */
    private boolean shouldSendNotification(Credential credential) {
        // Use last updated/created date as the basis for expiration
        LocalDateTime referenceDate = credential.getUpdatedAt() != null ? credential.getUpdatedAt()
                : credential.getCreatedAt();

        if (referenceDate == null) {
            return false;
        }

        // Calculate days until expiration
        LocalDateTime expiryDate = referenceDate.plusDays(PasswordExpiry.DEFAULT_PASSWORD_EXPIRY_DAYS);
        LocalDateTime now = LocalDateTime.now();
        long daysUntilExpiry = ChronoUnit.DAYS.between(now, expiryDate);

        // Check if we should send notification based on the days left
        return daysUntilExpiry <= PasswordExpiry.NOTIFICATION_THRESHOLD_EXPIRED
                || daysUntilExpiry == PasswordExpiry.NOTIFICATION_THRESHOLD_FIFTH
                || daysUntilExpiry == PasswordExpiry.NOTIFICATION_THRESHOLD_FOURTH
                || daysUntilExpiry == PasswordExpiry.NOTIFICATION_THRESHOLD_THIRD
                || daysUntilExpiry == PasswordExpiry.NOTIFICATION_THRESHOLD_SECOND
                || daysUntilExpiry == PasswordExpiry.NOTIFICATION_THRESHOLD_FIRST;
    }

    /**
     * Send a password expiry notification for a credential
     * 
     * @param credential The decrypted credential
     * @throws Exception If sending fails
     */
    private void sendPasswordExpiryNotification(Credential credential) throws Exception {
        // Use last updated/created date as the basis for expiration
        LocalDateTime referenceDate = credential.getUpdatedAt() != null ? credential.getUpdatedAt()
                : credential.getCreatedAt();

        // Calculate days until expiration
        LocalDateTime expiryDate = referenceDate.plusDays(PasswordExpiry.DEFAULT_PASSWORD_EXPIRY_DAYS);
        LocalDateTime now = LocalDateTime.now();
        int daysUntilExpiry = (int) ChronoUnit.DAYS.between(now, expiryDate);

        String username = credential.getUsername() != null ? credential.getUsername() : "Unknown account";

        Map<String, Object> metadata = new HashMap<>();
        metadata.put("credentialId", credential.getId());
        metadata.put("vaultId", credential.getVaultId());
        metadata.put("daysUntilExpiry", daysUntilExpiry);
        metadata.put("expiryDate", expiryDate.toString());
        metadata.put("thresholdTriggered", getThresholdName(daysUntilExpiry));

        String metadataJson = objectMapper.writeValueAsString(metadata);

        if (daysUntilExpiry <= 0) {
            // Password is already expired
            notificationCreationService.createPasswordExpiryNotification(credential.getUserId(), username,
                    credential.getVaultId(), credential.getId(), true, metadataJson);
        } else {
            // Password will expire soon
            notificationCreationService.createPasswordExpiryNotification(credential.getUserId(), username,
                    credential.getVaultId(), credential.getId(), false, daysUntilExpiry, metadataJson);
        }

        logger.info("Sent password expiry notification for credential {} ({}) - {} days until expiry",
                credential.getId(), username, daysUntilExpiry);
    }

    /**
     * Get a readable name for the threshold that triggered this notification
     * 
     * @param daysUntilExpiry Days until expiration
     * @return String name of threshold
     */
    private String getThresholdName(int daysUntilExpiry) {
        if (daysUntilExpiry <= 0)
            return "EXPIRED";
        if (daysUntilExpiry == 1)
            return "ONE_DAY";
        if (daysUntilExpiry == 2)
            return "TWO_DAYS";
        if (daysUntilExpiry == 3)
            return "THREE_DAYS";
        if (daysUntilExpiry == 7)
            return "ONE_WEEK";
        if (daysUntilExpiry == 14)
            return "TWO_WEEKS";
        return "CUSTOM";
    }
}