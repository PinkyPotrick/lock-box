package com.lockbox.service.notification;

import com.lockbox.dto.notification.NotificationResponseDTO;

public interface NotificationCreationService {

    NotificationResponseDTO createNewLoginNotification(String userId, String ipAddress) throws Exception;

    NotificationResponseDTO createFailedLoginAttemptsNotification(String userId, int attemptCount, String ipAddress)
            throws Exception;

    NotificationResponseDTO createPasswordChangedNotification(String userId) throws Exception;

    NotificationResponseDTO createAccountLockedNotification(String userId) throws Exception;

    NotificationResponseDTO createSuspiciousActivityNotification(String userId, String ipAddress, String metadata)
            throws Exception;

    NotificationResponseDTO createVaultDeletedNotification(String userId, String vaultName, int credentialCount)
            throws Exception;

    NotificationResponseDTO createCredentialUpdatedNotification(String userId, String username, String vaultName,
            String credentialId, String vaultId) throws Exception;

    NotificationResponseDTO createCredentialDeletedNotification(String userId, String username, String vaultName)
            throws Exception;

    NotificationResponseDTO createFrequentChangesNotification(String userId) throws Exception;

    NotificationResponseDTO createDataBreachNotification(String userId, String serviceName) throws Exception;

    NotificationResponseDTO createRecoveryAttemptNotification(String userId) throws Exception;
}