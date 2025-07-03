package com.lockbox.service.notification;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.model.Notification;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.service.encryption.RSAKeyPairService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link NotificationServerEncryptionService} interface. Provides methods to encrypt and decrypt
 * {@link Notification} data for secure storage in the database. Uses AES-CBC encryption to secure sensitive
 * notification data.
 */
@Service
public class NotificationServerEncryptionServiceImpl implements NotificationServerEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(NotificationServerEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    @Autowired
    private RSAKeyPairService rsaKeyPairService;

    /**
     * Encrypts sensitive notification data before storing in the database. Uses AES-CBC to encrypt sensitive fields.
     * 
     * @param notification - The notification with plaintext data to be encrypted
     * @return {@link Notification} object with sensitive fields encrypted
     * @throws Exception If encryption fails
     */
    @Override
    public Notification encryptServerData(Notification notification) throws Exception {
        try {
            long startTime = System.currentTimeMillis();
            Notification encryptedNotification = new Notification();

            // Copy non-encrypted fields
            encryptedNotification.setId(notification.getId());
            encryptedNotification.setUser(notification.getUser());
            encryptedNotification.setType(notification.getType());
            encryptedNotification.setResourceType(notification.getResourceType());
            encryptedNotification.setPriority(notification.getPriority());
            encryptedNotification.setStatus(notification.getStatus());
            encryptedNotification.setCreatedAt(notification.getCreatedAt());
            encryptedNotification.setReadAt(notification.getReadAt());
            encryptedNotification.setSentViaEmail(notification.getSentViaEmail());

            // Generate AES key for encrypting sensitive fields
            SecretKey aesKey = EncryptionUtils.generateAESKey();
            String serverPublicKeyPem = rsaKeyPairService.getPublicKeyInPEM(rsaKeyPairService.getPublicKey());

            // Encrypt sensitive fields
            if (notification.getTitle() != null) {
                encryptedNotification
                        .setTitle(genericEncryptionService.encryptStringWithAESCBC(notification.getTitle(), aesKey));
            }

            if (notification.getMessage() != null) {
                encryptedNotification.setMessage(
                        genericEncryptionService.encryptStringWithAESCBC(notification.getMessage(), aesKey));
            }

            if (notification.getResourceId() != null) {
                encryptedNotification.setResourceId(
                        genericEncryptionService.encryptStringWithAESCBC(notification.getResourceId(), aesKey));
            }

            if (notification.getActionLink() != null) {
                encryptedNotification.setActionLink(
                        genericEncryptionService.encryptStringWithAESCBC(notification.getActionLink(), aesKey));
            }

            if (notification.getMetadata() != null) {
                encryptedNotification.setMetadata(
                        genericEncryptionService.encryptStringWithAESCBC(notification.getMetadata(), aesKey));
            }

            // Encrypt the AES key with RSA
            encryptedNotification.setAesKey(rsaKeyPairService
                    .encryptRSAWithPublicKey(EncryptionUtils.getAESKeyString(aesKey), serverPublicKeyPem));

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Notification server encryption process completed in {} ms", duration);

            return encryptedNotification;
        } catch (Exception e) {
            logger.error("Error encrypting notification data: {}", e.getMessage(), e);
            throw new Exception("Error encrypting notification data", e);
        }
    }

    /**
     * Decrypts encrypted notification data after retrieving from the database. Uses AES-CBC to decrypt sensitive
     * fields.
     * 
     * @param notification - The notification with encrypted data to be decrypted
     * @return {@link Notification} object with decrypted sensitive fields
     * @throws Exception If decryption fails
     */
    @Override
    public Notification decryptServerData(Notification notification) throws Exception {
        try {
            long startTime = System.currentTimeMillis();
            Notification decryptedNotification = new Notification();

            // Decrypt the notification AES key used to encrypt sensitive fields
            String aesKeyString = rsaKeyPairService.decryptRSAWithServerPrivateKey(notification.getAesKey());
            SecretKey notificationAesKey = EncryptionUtils.getAESKeyFromString(aesKeyString);

            // Copy non-encrypted fields
            decryptedNotification.setId(notification.getId());
            decryptedNotification.setUser(notification.getUser());
            decryptedNotification.setType(notification.getType());
            decryptedNotification.setResourceType(notification.getResourceType());
            decryptedNotification.setPriority(notification.getPriority());
            decryptedNotification.setStatus(notification.getStatus());
            decryptedNotification.setCreatedAt(notification.getCreatedAt());
            decryptedNotification.setReadAt(notification.getReadAt());
            decryptedNotification.setSentViaEmail(notification.getSentViaEmail());

            // Decrypt sensitive fields
            if (notification.getTitle() != null) {
                decryptedNotification.setTitle(
                        genericEncryptionService.decryptStringWithAESCBC(notification.getTitle(), notificationAesKey));
            }

            if (notification.getMessage() != null) {
                decryptedNotification.setMessage(genericEncryptionService
                        .decryptStringWithAESCBC(notification.getMessage(), notificationAesKey));
            }

            if (notification.getResourceId() != null) {
                decryptedNotification.setResourceId(genericEncryptionService
                        .decryptStringWithAESCBC(notification.getResourceId(), notificationAesKey));
            }

            if (notification.getActionLink() != null) {
                decryptedNotification.setActionLink(genericEncryptionService
                        .decryptStringWithAESCBC(notification.getActionLink(), notificationAesKey));
            }

            if (notification.getMetadata() != null) {
                decryptedNotification.setMetadata(genericEncryptionService
                        .decryptStringWithAESCBC(notification.getMetadata(), notificationAesKey));
            }

            long duration = System.currentTimeMillis() - startTime;
            logger.info("Notification server decryption process completed in {} ms", duration);

            return decryptedNotification;
        } catch (Exception e) {
            logger.error("Error decrypting notification data: {}", e.getMessage(), e);
            throw new Exception("Error decrypting notification data", e);
        }
    }
}