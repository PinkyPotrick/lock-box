package com.lockbox.service.notification;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.notification.NotificationDTO;
import com.lockbox.dto.notification.NotificationResponseDTO;
import com.lockbox.model.enums.NotificationPriority;
import com.lockbox.model.enums.NotificationStatus;
import com.lockbox.model.enums.NotificationType;
import com.lockbox.model.enums.ResourceType;
import com.lockbox.utils.AppConstants.NotificationMessages;

/**
 * Implementation of {@link NotificationCreationService} interface. Creates standardized notifications for common
 * events.
 */
@Service
public class NotificationCreationServiceImpl implements NotificationCreationService {

    @Autowired
    private NotificationService notificationService;

    /**
     * Create a notification for a new login from an unknown device or IP address.
     * 
     * @param userId    - The user ID
     * @param ipAddress - The IP address of the new login
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createNewLoginNotification(String userId, String ipAddress) throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.SECURITY_ALERT);
        dto.setTitle(NotificationMessages.NEW_LOGIN_TITLE);
        dto.setMessage(String.format(NotificationMessages.NEW_LOGIN_MESSAGE, ipAddress));
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.HIGH);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.USER);
        dto.setResourceId(userId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(true);
        dto.setActionLink(null); // No specific action link for new login notifications;

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for multiple failed login attempts.
     * 
     * @param userId       - The user ID
     * @param attemptCount - The number of failed attempts
     * @param ipAddress    - The IP address of the last failed attempt
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createFailedLoginAttemptsNotification(String userId, int attemptCount,
            String ipAddress) throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.SECURITY_ALERT);
        dto.setTitle(NotificationMessages.FAILED_LOGIN_TITLE);
        dto.setMessage(String.format(NotificationMessages.FAILED_LOGIN_MESSAGE, attemptCount, ipAddress));
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.HIGH);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.USER);
        dto.setResourceId(userId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(true);
        dto.setActionLink(null); // No specific action link for failed login attempts

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for a password change.
     * 
     * @param userId - The user ID
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createPasswordChangedNotification(String userId) throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.ACCOUNT);
        dto.setTitle(NotificationMessages.PASSWORD_CHANGE_TITLE);
        dto.setMessage(NotificationMessages.PASSWORD_CHANGE_MESSAGE);
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.MEDIUM);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.USER);
        dto.setResourceId(userId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(true);

        // Create notification link to account settings
        dto.setActionLink("/profile");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for account lockout.
     * 
     * @param userId - The user ID
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createAccountLockedNotification(String userId) throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.SECURITY_ALERT);
        dto.setTitle(NotificationMessages.ACCOUNT_LOCKED_TITLE);
        dto.setMessage(NotificationMessages.ACCOUNT_LOCKED_MESSAGE);
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.CRITICAL);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.USER);
        dto.setResourceId(userId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(true);

        // Create notification link to reset password page
        dto.setActionLink("/profile");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for a deleted vault.
     * 
     * @param userId          - The user ID
     * @param vaultName       - The name of the deleted vault
     * @param credentialCount - The number of credentials that were in the vault
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createVaultDeletedNotification(String userId, String vaultName, int credentialCount)
            throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.CONTENT);
        dto.setTitle(NotificationMessages.VAULT_DELETED_TITLE);
        dto.setMessage(String.format(NotificationMessages.VAULT_DELETED_MESSAGE, vaultName, credentialCount));
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.MEDIUM);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.VAULT);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(false);

        // Create notification link to vaults page
        dto.setActionLink("/vaults");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for an updated credential.
     * 
     * @param userId         - The user ID
     * @param credentialName - The name of the updated credential
     * @param vaultName      - The name of the vault containing the credential
     * @param credentialId   - The ID of the updated credential
     * @param vaultId        - The ID of the vault containing the credential
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createCredentialUpdatedNotification(String userId, String username, String vaultName,
            String credentialId, String vaultId) throws Exception {

        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.CONTENT);
        dto.setTitle(NotificationMessages.CREDENTIAL_UPDATED_TITLE);
        dto.setMessage(String.format(NotificationMessages.CREDENTIAL_UPDATED_MESSAGE, username, vaultName));
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.LOW);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.CREDENTIAL);
        dto.setResourceId(credentialId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(false);

        // Create notification link to the credential
        dto.setActionLink("/vaults/" + vaultId + "/credentials");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for a deleted credential.
     * 
     * @param userId         - The user ID
     * @param credentialName - The name of the deleted credential
     * @param vaultName      - The name of the vault that contained the credential
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createCredentialDeletedNotification(String userId, String username, String vaultName)
            throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.CONTENT);
        dto.setTitle(NotificationMessages.CREDENTIAL_DELETED_TITLE);
        dto.setMessage(String.format(NotificationMessages.CREDENTIAL_DELETED_MESSAGE, username, vaultName));
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.LOW);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.CREDENTIAL);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(false);

        // Create notification link to the vault
        dto.setActionLink("/vaults");
        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for suspicious activity detection.
     * 
     * @param userId    - The user ID
     * @param ipAddress - The IP address from which suspicious activity was detected
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createSuspiciousActivityNotification(String userId, String ipAddress,
            String metadata) throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.SECURITY_ALERT);
        dto.setTitle(NotificationMessages.SUSPICIOUS_ACTIVITY_TITLE);
        dto.setMessage(String.format(NotificationMessages.SUSPICIOUS_ACTIVITY_MESSAGE, ipAddress));
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.HIGH);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.USER);
        dto.setResourceId(userId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(true);
        dto.setMetadata(metadata);

        // Create notification link to security settings
        dto.setActionLink("/profile");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for frequent security changes.
     * 
     * @param userId - The user ID
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createFrequentChangesNotification(String userId) throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.SECURITY_ALERT);
        dto.setTitle(NotificationMessages.FREQUENT_CHANGES_TITLE);
        dto.setMessage(NotificationMessages.FREQUENT_CHANGES_MESSAGE);
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.HIGH);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.USER);
        dto.setResourceId(userId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(true);

        // Create notification link to security settings
        dto.setActionLink("/profile");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for potential data breach.
     * 
     * @param userId      - The user ID
     * @param serviceName - The name of the service with a potential breach
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createDataBreachNotification(String userId, String serviceName) throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.SECURITY_ALERT);
        dto.setTitle(NotificationMessages.DATA_BREACH_TITLE);
        dto.setMessage(String.format(NotificationMessages.DATA_BREACH_MESSAGE, serviceName));
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.HIGH);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.USER);
        dto.setResourceId(userId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(true);

        // Create notification link to passwords page
        dto.setActionLink("/profile");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for account recovery attempt.
     * 
     * @param userId - The user ID
     * @return Created {@link NotificationResponseDTO}
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createRecoveryAttemptNotification(String userId) throws Exception {
        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.SECURITY_ALERT);
        dto.setTitle(NotificationMessages.RECOVERY_ATTEMPT_TITLE);
        dto.setMessage(NotificationMessages.RECOVERY_ATTEMPT_MESSAGE);
        dto.setUserId(userId);
        dto.setPriority(NotificationPriority.HIGH);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.USER);
        dto.setResourceId(userId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(true);

        // Create notification link to security settings
        dto.setActionLink("/profile");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for a password that will expire soon.
     * 
     * @param userId          - The user ID
     * @param username        - The credential username
     * @param vaultId         - The vault ID
     * @param credentialId    - The credential ID
     * @param isExpired       - Whether the password has already expired
     * @param daysUntilExpiry - Days until the password expires
     * @param metadata        - JSON string with additional metadata
     * @return Created notification response
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createPasswordExpiryNotification(String userId, String username, String vaultId,
            String credentialId, boolean isExpired, int daysUntilExpiry, String metadata) throws Exception {

        NotificationDTO dto = new NotificationDTO();
        dto.setType(NotificationType.PASSWORD_EXPIRY);

        if (isExpired) {
            dto.setTitle(NotificationMessages.PASSWORD_EXPIRED_TITLE);
            dto.setMessage(String.format(NotificationMessages.PASSWORD_EXPIRED_MESSAGE, username));
            dto.setPriority(NotificationPriority.HIGH);
        } else {
            dto.setTitle(NotificationMessages.PASSWORD_EXPIRY_TITLE);
            dto.setMessage(String.format(NotificationMessages.PASSWORD_EXPIRY_MESSAGE, username, daysUntilExpiry));
            if (daysUntilExpiry <= 3) {
                dto.setPriority(NotificationPriority.HIGH);
            } else if (daysUntilExpiry <= 7) {
                dto.setPriority(NotificationPriority.MEDIUM);
            } else {
                dto.setPriority(NotificationPriority.LOW);
            }
        }

        dto.setUserId(userId);
        dto.setStatus(NotificationStatus.UNREAD);
        dto.setResourceType(ResourceType.CREDENTIAL);
        dto.setResourceId(credentialId);
        dto.setCreatedAt(LocalDateTime.now());
        dto.setSentViaEmail(null);
        dto.setMetadata(metadata);

        // Create action link to the credential
        dto.setActionLink("/vaults/" + vaultId + "/credentials");

        return notificationService.createNotificationInternal(dto, userId);
    }

    /**
     * Create a notification for a password that has already expired.
     * 
     * @param userId       - The user ID
     * @param username     - The credential username
     * @param vaultId      - The vault ID
     * @param credentialId - The credential ID
     * @param isExpired    - Whether the password has already expired
     * @param metadata     - JSON string with additional metadata
     * @return Created notification response
     * @throws Exception If creation fails
     */
    @Override
    public NotificationResponseDTO createPasswordExpiryNotification(String userId, String username, String vaultId,
            String credentialId, boolean isExpired, String metadata) throws Exception {

        return createPasswordExpiryNotification(userId, username, vaultId, credentialId, true, 0, metadata);
    }
}