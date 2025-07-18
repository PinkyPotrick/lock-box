package com.lockbox.service.notification;

import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.lockbox.dto.encryption.EncryptedDataAesCbcMapper;
import com.lockbox.dto.notification.NotificationDTO;
import com.lockbox.dto.notification.NotificationListResponseDTO;
import com.lockbox.dto.notification.NotificationRequestDTO;
import com.lockbox.dto.notification.NotificationResponseDTO;
import com.lockbox.model.EncryptedDataAesCbc;
import com.lockbox.service.encryption.GenericEncryptionService;
import com.lockbox.utils.EncryptionUtils;

/**
 * Implementation of the {@link NotificationClientEncryptionService} interface. Provides methods for encrypting and
 * decrypting notification data for secure transmission between client and server.
 */
@Service
public class NotificationClientEncryptionServiceImpl implements NotificationClientEncryptionService {

    private final Logger logger = LoggerFactory.getLogger(NotificationClientEncryptionServiceImpl.class);

    @Autowired
    private GenericEncryptionService genericEncryptionService;

    /**
     * Encrypts a notification DTO for client response. Uses AES encryption to secure the notification data.
     * 
     * @param notificationDTO - The notification data to encrypt
     * @return Encrypted {@link NotificationResponseDTO} ready for transmission to client
     * @throws Exception If encryption fails
     */
    @Override
    public NotificationResponseDTO encryptNotificationForClient(NotificationDTO notificationDTO) throws Exception {
        if (notificationDTO == null) {
            return null;
        }

        // Generate a helper AES key
        long startTime = System.currentTimeMillis();
        SecretKey aesKey = EncryptionUtils.generateAESKey();
        EncryptedDataAesCbcMapper encryptedDataAesCbcMapper = new EncryptedDataAesCbcMapper();
        NotificationResponseDTO responseDTO = new NotificationResponseDTO();

        // Set basic field values that don't need encryption
        responseDTO.setId(notificationDTO.getId());
        responseDTO.setUserId(notificationDTO.getUserId());
        responseDTO.setType(notificationDTO.getType());
        responseDTO.setResourceType(notificationDTO.getResourceType());
        responseDTO.setPriority(notificationDTO.getPriority());
        responseDTO.setStatus(notificationDTO.getStatus());
        responseDTO.setCreatedAt(notificationDTO.getCreatedAt());
        responseDTO.setReadAt(notificationDTO.getReadAt());
        responseDTO.setSentViaEmail(notificationDTO.getSentViaEmail());

        // Encrypt fields that need encryption
        if (notificationDTO.getTitle() != null) {
            EncryptedDataAesCbc encryptedTitle = genericEncryptionService
                    .encryptDTOWithAESCBC(notificationDTO.getTitle(), EncryptedDataAesCbc.class, aesKey);
            responseDTO.setEncryptedTitle(encryptedDataAesCbcMapper.toDto(encryptedTitle));
        }

        if (notificationDTO.getMessage() != null) {
            EncryptedDataAesCbc encryptedMessage = genericEncryptionService
                    .encryptDTOWithAESCBC(notificationDTO.getMessage(), EncryptedDataAesCbc.class, aesKey);
            responseDTO.setEncryptedMessage(encryptedDataAesCbcMapper.toDto(encryptedMessage));
        }

        if (notificationDTO.getResourceId() != null) {
            EncryptedDataAesCbc encryptedResourceId = genericEncryptionService
                    .encryptDTOWithAESCBC(notificationDTO.getResourceId(), EncryptedDataAesCbc.class, aesKey);
            responseDTO.setEncryptedResourceId(encryptedDataAesCbcMapper.toDto(encryptedResourceId));
        }

        if (notificationDTO.getActionLink() != null) {
            EncryptedDataAesCbc encryptedActionLink = genericEncryptionService
                    .encryptDTOWithAESCBC(notificationDTO.getActionLink(), EncryptedDataAesCbc.class, aesKey);
            responseDTO.setEncryptedActionLink(encryptedDataAesCbcMapper.toDto(encryptedActionLink));
        }

        if (notificationDTO.getMetadata() != null) {
            EncryptedDataAesCbc encryptedMetadata = genericEncryptionService
                    .encryptDTOWithAESCBC(notificationDTO.getMetadata(), EncryptedDataAesCbc.class, aesKey);
            responseDTO.setEncryptedMetadata(encryptedDataAesCbcMapper.toDto(encryptedMetadata));
        }

        // Set the helper AES key used for encryption
        responseDTO.setHelperAesKey(EncryptionUtils.getAESKeyString(aesKey));

        long endTime = System.currentTimeMillis();
        logger.info("Notification client response encryption process completed in {} ms", endTime - startTime);

        return responseDTO;
    }

    /**
     * Encrypts a list of notification DTOs for client response.
     * 
     * @param notificationDTOs - The list of notification data to encrypt
     * @return {@link NotificationListResponseDTO} containing encrypted notifications ready for transmission
     * @throws Exception If encryption fails
     */
    @Override
    public NotificationListResponseDTO encryptNotificationListForClient(List<NotificationDTO> notificationDTOs)
            throws Exception {
        if (notificationDTOs == null) {
            return null;
        }

        long startTime = System.currentTimeMillis();
        List<NotificationResponseDTO> encryptedNotifications = new ArrayList<>();

        for (NotificationDTO notificationDTO : notificationDTOs) {
            encryptedNotifications.add(encryptNotificationForClient(notificationDTO));
        }

        long endTime = System.currentTimeMillis();
        logger.info("Notification client list encryption process completed in {} ms", endTime - startTime);

        return new NotificationListResponseDTO(encryptedNotifications, notificationDTOs.size());
    }

    /**
     * Decrypts a notification request DTO from the client.
     * 
     * @param requestDTO - The encrypted notification request from client
     * @return Decrypted {@link NotificationDTO}
     * @throws Exception If decryption fails
     */
    @Override
    public NotificationDTO decryptNotificationFromClient(NotificationRequestDTO requestDTO) throws Exception {
        long startTime = System.currentTimeMillis();

        if (requestDTO == null || requestDTO.getHelperAesKey() == null) {
            return null;
        }

        NotificationDTO notificationDTO = new NotificationDTO();

        // Copy non-encrypted fields
        notificationDTO.setUserId(requestDTO.getUserId());
        notificationDTO.setType(requestDTO.getType());
        notificationDTO.setResourceType(requestDTO.getResourceType());
        notificationDTO.setPriority(requestDTO.getPriority());
        notificationDTO.setSentViaEmail(requestDTO.getSentViaEmail());

        // Decrypt encrypted fields
        if (requestDTO.getEncryptedTitle() != null) {
            notificationDTO.setTitle(genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedTitle(),
                    String.class, requestDTO.getHelperAesKey()));
        }

        if (requestDTO.getEncryptedMessage() != null) {
            notificationDTO.setMessage(genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedMessage(),
                    String.class, requestDTO.getHelperAesKey()));
        }

        if (requestDTO.getEncryptedResourceId() != null) {
            notificationDTO.setResourceId(genericEncryptionService.decryptDTOWithAESCBC(
                    requestDTO.getEncryptedResourceId(), String.class, requestDTO.getHelperAesKey()));
        }

        if (requestDTO.getEncryptedActionLink() != null) {
            notificationDTO.setActionLink(genericEncryptionService.decryptDTOWithAESCBC(
                    requestDTO.getEncryptedActionLink(), String.class, requestDTO.getHelperAesKey()));
        }

        if (requestDTO.getEncryptedMetadata() != null) {
            notificationDTO.setMetadata(genericEncryptionService.decryptDTOWithAESCBC(requestDTO.getEncryptedMetadata(),
                    String.class, requestDTO.getHelperAesKey()));
        }

        long endTime = System.currentTimeMillis();
        logger.info("Notification client decryption process completed in {} ms", endTime - startTime);

        return notificationDTO;
    }
}