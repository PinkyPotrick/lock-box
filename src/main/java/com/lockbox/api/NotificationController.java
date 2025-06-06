package com.lockbox.api;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.notification.NotificationListResponseDTO;
import com.lockbox.dto.notification.NotificationMarkReadRequestDTO;
import com.lockbox.dto.notification.NotificationResponseDTO;
import com.lockbox.dto.notification.NotificationUnreadCountResponseDTO;
import com.lockbox.model.NotificationPriority;
import com.lockbox.model.NotificationStatus;
import com.lockbox.model.NotificationType;
import com.lockbox.service.notification.NotificationService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;
import com.lockbox.validators.NotificationValidator;

@RestController
@RequestMapping("/api/notifications")
public class NotificationController {

    private final Logger logger = LoggerFactory.getLogger(NotificationController.class);

    @Autowired
    private NotificationService notificationService;

    @Autowired
    private SecurityUtils securityUtils;

    @Autowired
    private NotificationValidator notificationValidator;

    @GetMapping
    public ResponseEntityDTO<NotificationListResponseDTO> getNotifications(
            @RequestParam(name = "status", required = false) String status,
            @RequestParam(name = "type", required = false) String type,
            @RequestParam(name = "priority", required = false) String priority,
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size) {

        try {
            String userId = securityUtils.getCurrentUserId();

            NotificationStatus statusEnum = status != null ? NotificationStatus.valueOf(status.toUpperCase()) : null;
            NotificationType typeEnum = type != null ? NotificationType.valueOf(type.toUpperCase()) : null;
            NotificationPriority priorityEnum = priority != null ? NotificationPriority.valueOf(priority.toUpperCase())
                    : null;

            NotificationListResponseDTO response = notificationService.findNotifications(userId, statusEnum, typeEnum,
                    priorityEnum, page, size);

            return new ResponseEntityBuilder<NotificationListResponseDTO>().setData(response)
                    .setMessage("Notifications retrieved successfully").build();
        } catch (Exception e) {
            logger.error("Error getting notifications: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to retrieve notifications");
        }
    }

    @GetMapping("/unread-count")
    public ResponseEntityDTO<NotificationUnreadCountResponseDTO> getUnreadCount() {
        try {
            String userId = securityUtils.getCurrentUserId();
            NotificationUnreadCountResponseDTO response = notificationService.getUnreadNotificationCount(userId);

            return new ResponseEntityBuilder<NotificationUnreadCountResponseDTO>().setData(response)
                    .setMessage("Unread count retrieved successfully").build();
        } catch (Exception e) {
            logger.error("Error getting unread notification count: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to retrieve unread count");
        }
    }

    @GetMapping("/{id}")
    public ResponseEntityDTO<NotificationResponseDTO> getNotificationById(@PathVariable String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            NotificationResponseDTO response = notificationService.findNotificationById(id, userId);

            return new ResponseEntityBuilder<NotificationResponseDTO>().setData(response)
                    .setMessage("Notification retrieved successfully").build();
        } catch (Exception e) {
            logger.error("Error getting notification {}: {}", id, e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to retrieve notification");
        }
    }

    @PutMapping("/read-status")
    public ResponseEntityDTO<Integer> markNotificationsReadStatus(
            @RequestBody NotificationMarkReadRequestDTO requestDTO) {
        try {
            String userId = securityUtils.getCurrentUserId();

            notificationValidator.validateMarkReadRequest(requestDTO);
            List<String> notificationIds = requestDTO.getNotificationIds();
            boolean markAsRead = requestDTO.isMarkAsRead();

            int updatedCount = notificationService.markNotificationsReadStatus(notificationIds, userId, markAsRead);

            return new ResponseEntityBuilder<Integer>().setData(updatedCount).setMessage(
                    "Successfully marked " + updatedCount + " notifications as " + (markAsRead ? "read" : "unread"))
                    .build();
        } catch (Exception e) {
            logger.error("Error marking notifications read status: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to update notification status");
        }
    }

    @PutMapping("/mark-all-read")
    public ResponseEntityDTO<Integer> markAllNotificationsAsRead() {
        try {
            String userId = securityUtils.getCurrentUserId();
            int updatedCount = notificationService.markAllNotificationsAsRead(userId);

            return new ResponseEntityBuilder<Integer>().setData(updatedCount)
                    .setMessage("Successfully marked all notifications as read").build();
        } catch (Exception e) {
            logger.error("Error marking all notifications as read: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to mark all notifications as read");
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ResponseEntityDTO<Void>> deleteNotification(@PathVariable String id) {
        try {
            String userId = securityUtils.getCurrentUserId();
            notificationService.deleteNotification(id, userId);

            ResponseEntityDTO<Void> response = new ResponseEntityBuilder<Void>()
                    .setMessage("Notification deleted successfully").build();

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error deleting notification {}: {}", id, e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(ResponseEntityBuilder.handleErrorDTO(e, "Failed to delete notification"));
        }
    }
}