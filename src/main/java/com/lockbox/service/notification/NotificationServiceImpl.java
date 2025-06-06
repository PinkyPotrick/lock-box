package com.lockbox.service.notification;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lockbox.dto.notification.NotificationDTO;
import com.lockbox.dto.notification.NotificationListResponseDTO;
import com.lockbox.dto.notification.NotificationMapper;
import com.lockbox.dto.notification.NotificationResponseDTO;
import com.lockbox.dto.notification.NotificationUnreadCountResponseDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.model.Notification;
import com.lockbox.model.NotificationPriority;
import com.lockbox.model.NotificationStatus;
import com.lockbox.model.NotificationType;
import com.lockbox.model.User;
import com.lockbox.repository.NotificationRepository;
import com.lockbox.repository.UserRepository;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.LogMessages;
import com.lockbox.validators.NotificationValidator;

/**
 * Implementation of the {@link NotificationService} interface for managing user notifications.
 */
@Service
public class NotificationServiceImpl implements NotificationService {

    private final Logger logger = LoggerFactory.getLogger(NotificationServiceImpl.class);

    @Autowired
    private NotificationRepository notificationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private NotificationMapper notificationMapper;

    @Autowired
    private NotificationValidator notificationValidator;

    @Autowired
    private NotificationServerEncryptionService notificationServerEncryptionService;

    @Autowired
    private NotificationClientEncryptionService notificationClientEncryptionService;

    /**
     * Find all notifications for a user with optional pagination and filtering.
     * 
     * @param userId   - The current user ID
     * @param status   - Optional filter for notification status
     * @param type     - Optional filter for notification type
     * @param priority - Optional filter for notification priority
     * @param page     - Optional page number (0-based index), can be null
     * @param size     - Optional page size, can be null
     * @return {@link NotificationListResponseDTO} containing encrypted notifications
     * @throws Exception If retrieval or encryption fails
     */
    @Override
    public NotificationListResponseDTO findNotifications(String userId, NotificationStatus status,
            NotificationType type, NotificationPriority priority, Integer page, Integer size) throws Exception {

        try {
            // Set default pagination values if not provided
            int pageNumber = page != null ? page : 0;
            int pageSize = size != null ? size : 10;

            // Create pageable object for pagination and sorting (newest first)
            Pageable pageable = PageRequest.of(pageNumber, pageSize, Sort.by("createdAt").descending());

            // Query the database based on filters
            Page<Notification> encryptedNotificationsPage;

            if (status != null) {
                encryptedNotificationsPage = notificationRepository.findByUserIdAndStatusOrderByCreatedAtDesc(userId,
                        status, pageable);
            } else if (type != null) {
                encryptedNotificationsPage = notificationRepository.findByUserIdAndTypeOrderByCreatedAtDesc(userId,
                        type, pageable);
            } else if (priority != null) {
                encryptedNotificationsPage = notificationRepository.findByUserIdAndPriorityOrderByCreatedAtDesc(userId,
                        priority, pageable);
            } else {
                encryptedNotificationsPage = notificationRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable);
            }

            // Decrypt each notification
            List<NotificationDTO> notificationDTOs = new ArrayList<>();
            for (Notification encryptedNotification : encryptedNotificationsPage.getContent()) {
                Notification decryptedNotification = notificationServerEncryptionService
                        .decryptServerData(encryptedNotification);
                NotificationDTO dto = notificationMapper.toDTO(decryptedNotification);
                notificationDTOs.add(dto);
            }

            // Encrypt for client and return
            return notificationClientEncryptionService.encryptNotificationListForClient(notificationDTOs);
        } catch (Exception e) {
            logger.error("Error retrieving notifications for user {}: {}", userId, e.getMessage(), e);
            throw new Exception("Error retrieving notifications", e);
        }
    }

    /**
     * Get the count of unread notifications for a user.
     * 
     * @param userId - The user ID
     * @return {@link NotificationUnreadCountResponseDTO} containing the unread count
     * @throws Exception If retrieval fails
     */
    @Override
    public NotificationUnreadCountResponseDTO getUnreadNotificationCount(String userId) throws Exception {
        try {
            int unreadCount = notificationRepository.countByUserIdAndStatus(userId, NotificationStatus.UNREAD);
            return new NotificationUnreadCountResponseDTO(unreadCount);
        } catch (Exception e) {
            logger.error("Error getting unread notification count for user {}: {}", userId, e.getMessage(), e);
            throw new Exception("Error getting unread notification count", e);
        }
    }

    /**
     * Create a new notification using a DTO directly (for internal system notifications).
     * 
     * @param notificationDTO - The notification data
     * @param userId          - The recipient user ID
     * @return Created {@link NotificationResponseDTO} with encryption
     * @throws Exception If validation, creation, or encryption fails
     */
    @Override
    @Transactional
    public NotificationResponseDTO createNotificationInternal(NotificationDTO notificationDTO, String userId)
            throws Exception {
        try {
            // Validate the notification data
            notificationValidator.validateNotificationDTO(notificationDTO);

            // Find the user
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new ValidationException(null, "User not found with ID: " + userId));

            // Set default status to unread if not specified
            if (notificationDTO.getStatus() == null) {
                notificationDTO.setStatus(NotificationStatus.UNREAD);
            }

            // Set created timestamp if not provided
            if (notificationDTO.getCreatedAt() == null) {
                notificationDTO.setCreatedAt(LocalDateTime.now());
            }

            // Convert to entity
            Notification notification = notificationMapper.toEntity(notificationDTO, user);

            // Encrypt sensitive data
            Notification encryptedNotification = notificationServerEncryptionService.encryptServerData(notification);

            // Save to database
            Notification savedNotification = notificationRepository.save(encryptedNotification);
            logger.info(LogMessages.NOTIFICATION_CREATE_SUCCESS, savedNotification.getId());

            // Decrypt for response
            Notification decryptedNotification = notificationServerEncryptionService
                    .decryptServerData(savedNotification);

            // Convert back to DTO
            NotificationDTO savedDTO = notificationMapper.toDTO(decryptedNotification);

            // Encrypt for client response
            return notificationClientEncryptionService.encryptNotificationForClient(savedDTO);
        } catch (Exception e) {
            logger.error("Error creating internal notification for user {}: {}", userId, e.getMessage(), e);
            throw new Exception("Error creating notification", e);
        }
    }

    /**
     * Mark notifications as read or unread.
     * 
     * @param notificationIds - List of notification IDs to update
     * @param userId          - The user ID for authorization
     * @param markAsRead      - True to mark as read, false to mark as unread
     * @return Number of notifications updated
     * @throws Exception If update fails
     */
    @Override
    @Transactional
    public int markNotificationsReadStatus(List<String> notificationIds, String userId, boolean markAsRead)
            throws Exception {
        try {
            // Check ownership of all notifications before updating
            for (String notificationId : notificationIds) {
                Optional<Notification> notificationOpt = notificationRepository.findById(notificationId);

                if (!notificationOpt.isPresent()) {
                    logger.warn(LogMessages.NOTIFICATION_NOT_FOUND, notificationId);
                    throw new Exception("Notification not found with ID: " + notificationId);
                }

                Notification notification = notificationOpt.get();

                if (!notification.getUser().getId().equals(userId)) {
                    logger.warn(LogMessages.NOTIFICATION_ACCESS_DENIED, userId, notificationId);
                    throw new SecurityException("Access denied");
                }
            }

            // Update the notifications
            int updatedCount;
            if (markAsRead) {
                updatedCount = notificationRepository.markNotificationsAsRead(notificationIds, LocalDateTime.now());
                logger.info(LogMessages.NOTIFICATION_MARK_READ_SUCCESS, updatedCount, "read");
            } else {
                updatedCount = notificationRepository.markNotificationsAsUnread(notificationIds);
                logger.info(LogMessages.NOTIFICATION_MARK_READ_SUCCESS, updatedCount, "unread");
            }

            return updatedCount;
        } catch (Exception e) {
            logger.error("Error marking notifications as {}: {}", markAsRead ? "read" : "unread", e.getMessage(), e);
            throw new Exception("Error updating notification status", e);
        }
    }

    /**
     * Mark all notifications as read for a user.
     * 
     * @param userId - The user ID
     * @return Number of notifications marked as read
     * @throws Exception If update fails
     */
    @Override
    @Transactional
    public int markAllNotificationsAsRead(String userId) throws Exception {
        try {
            int updatedCount = notificationRepository.markAllNotificationsAsRead(userId, LocalDateTime.now());
            logger.info(LogMessages.NOTIFICATION_MARK_ALL_READ_SUCCESS, userId);
            return updatedCount;
        } catch (Exception e) {
            logger.error("Error marking all notifications as read for user {}: {}", userId, e.getMessage(), e);
            throw new Exception("Error marking all notifications as read", e);
        }
    }

    /**
     * Delete expired notifications based on priority-specific expiry periods.
     * 
     * @return Number of notifications deleted
     * @throws Exception If deletion fails
     */
    @Override
    @Transactional
    public int cleanupExpiredNotifications() throws Exception {
        try {
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime lowPriorityCutoff = now.minusDays(AppConstants.NotificationExpiry.LOW_PRIORITY_DAYS);
            LocalDateTime mediumPriorityCutoff = now.minusDays(AppConstants.NotificationExpiry.MEDIUM_PRIORITY_DAYS);
            LocalDateTime highPriorityCutoff = now.minusDays(AppConstants.NotificationExpiry.HIGH_PRIORITY_DAYS);

            int deletedCount = notificationRepository.deleteExpiredNotifications(lowPriorityCutoff,
                    mediumPriorityCutoff, highPriorityCutoff);

            logger.info(LogMessages.NOTIFICATION_DELETE_EXPIRED, deletedCount);
            return deletedCount;
        } catch (Exception e) {
            logger.error("Error cleaning up expired notifications: {}", e.getMessage(), e);
            throw new Exception("Error cleaning up expired notifications", e);
        }
    }

    /**
     * Get a specific notification by ID.
     * 
     * @param id     - The notification ID
     * @param userId - The user ID for authorization
     * @return {@link NotificationResponseDTO} with encryption
     * @throws Exception If not found, access denied, or encryption fails
     */
    @Override
    public NotificationResponseDTO findNotificationById(String id, String userId) throws Exception {
        try {
            // Find the notification
            Optional<Notification> notificationOpt = notificationRepository.findById(id);

            if (!notificationOpt.isPresent()) {
                logger.warn(LogMessages.NOTIFICATION_NOT_FOUND, id);
                throw new Exception("Notification not found with ID: " + id);
            }

            Notification notification = notificationOpt.get();

            // Verify user ownership
            if (!notification.getUser().getId().equals(userId)) {
                logger.warn(LogMessages.NOTIFICATION_ACCESS_DENIED, userId, id);
                throw new SecurityException("Access denied");
            }

            // Decrypt notification data
            Notification decryptedNotification = notificationServerEncryptionService.decryptServerData(notification);

            // Convert to DTO
            NotificationDTO notificationDTO = notificationMapper.toDTO(decryptedNotification);

            // Encrypt for client
            return notificationClientEncryptionService.encryptNotificationForClient(notificationDTO);
        } catch (Exception e) {
            logger.error("Error finding notification {}: {}", id, e.getMessage(), e);
            throw new Exception("Error finding notification", e);
        }
    }

    /**
     * Delete a specific notification.
     * 
     * @param id     - The notification ID
     * @param userId - The user ID for authorization
     * @throws Exception If not found, access denied, or deletion fails
     */
    @Override
    @Transactional
    public void deleteNotification(String id, String userId) throws Exception {
        try {
            // Find the notification
            Optional<Notification> notificationOpt = notificationRepository.findById(id);

            if (!notificationOpt.isPresent()) {
                logger.warn(LogMessages.NOTIFICATION_NOT_FOUND, id);
                throw new Exception("Notification not found with ID: " + id);
            }

            Notification notification = notificationOpt.get();

            // Verify user ownership
            if (!notification.getUser().getId().equals(userId)) {
                logger.warn(LogMessages.NOTIFICATION_ACCESS_DENIED, userId, id);
                throw new SecurityException("Access denied");
            }

            // Delete the notification
            notificationRepository.deleteById(id);
            logger.info(LogMessages.NOTIFICATION_DELETE_SUCCESS, id);
        } catch (Exception e) {
            logger.error("Error deleting notification {}: {}", id, e.getMessage(), e);
            throw new Exception("Error deleting notification", e);
        }
    }
}