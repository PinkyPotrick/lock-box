package com.lockbox.service.notification;

import java.util.List;

import com.lockbox.dto.notification.NotificationDTO;
import com.lockbox.dto.notification.NotificationListResponseDTO;
import com.lockbox.dto.notification.NotificationRequestDTO;
import com.lockbox.dto.notification.NotificationResponseDTO;

public interface NotificationClientEncryptionService {

    NotificationResponseDTO encryptNotificationForClient(NotificationDTO notificationDTO) throws Exception;

    NotificationListResponseDTO encryptNotificationListForClient(List<NotificationDTO> notificationDTOs)
            throws Exception;

    NotificationDTO decryptNotificationFromClient(NotificationRequestDTO requestDTO) throws Exception;
}