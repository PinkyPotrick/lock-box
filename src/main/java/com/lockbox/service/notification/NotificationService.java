package com.lockbox.service.notification;

import java.util.List;

import com.lockbox.dto.notification.NotificationDTO;
import com.lockbox.dto.notification.NotificationListResponseDTO;
import com.lockbox.dto.notification.NotificationResponseDTO;
import com.lockbox.dto.notification.NotificationUnreadCountResponseDTO;
import com.lockbox.model.NotificationPriority;
import com.lockbox.model.NotificationStatus;
import com.lockbox.model.NotificationType;

public interface NotificationService {

    NotificationListResponseDTO findNotifications(String userId, NotificationStatus status, NotificationType type,
            NotificationPriority priority, Integer page, Integer size) throws Exception;

    NotificationUnreadCountResponseDTO getUnreadNotificationCount(String userId) throws Exception;

    NotificationResponseDTO createNotificationInternal(NotificationDTO notificationDTO, String userId) throws Exception;

    int markNotificationsReadStatus(List<String> notificationIds, String userId, boolean markAsRead) throws Exception;

    int markAllNotificationsAsRead(String userId) throws Exception;

    int cleanupExpiredNotifications() throws Exception;

    NotificationResponseDTO findNotificationById(String id, String userId) throws Exception;

    void deleteNotification(String id, String userId) throws Exception;
}