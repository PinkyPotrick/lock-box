package com.lockbox.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.lockbox.model.Notification;
import com.lockbox.model.NotificationPriority;
import com.lockbox.model.NotificationStatus;
import com.lockbox.model.NotificationType;

/**
 * Repository interface for {@link Notification} entities.
 */
@Repository
public interface NotificationRepository extends JpaRepository<Notification, String> {

    /**
     * Find all notifications by user ID with pagination
     * 
     * @param userId   - The user ID
     * @param pageable - Pagination information
     * @return Page of notifications
     */
    Page<Notification> findByUserIdOrderByCreatedAtDesc(String userId, Pageable pageable);

    /**
     * Find all notifications by user ID, filtered by status with pagination
     * 
     * @param userId   - The user ID
     * @param status   - The notification status
     * @param pageable - Pagination information
     * @return Page of notifications
     */
    Page<Notification> findByUserIdAndStatusOrderByCreatedAtDesc(String userId, NotificationStatus status,
            Pageable pageable);

    /**
     * Find all notifications by user ID, filtered by type with pagination
     * 
     * @param userId   - The user ID
     * @param type     - The notification type
     * @param pageable - Pagination information
     * @return Page of notifications
     */
    Page<Notification> findByUserIdAndTypeOrderByCreatedAtDesc(String userId, NotificationType type, Pageable pageable);

    /**
     * Find all notifications by user ID, filtered by priority with pagination
     * 
     * @param userId   - The user ID
     * @param priority - The notification priority
     * @param pageable - Pagination information
     * @return Page of notifications
     */
    Page<Notification> findByUserIdAndPriorityOrderByCreatedAtDesc(String userId, NotificationPriority priority,
            Pageable pageable);

    /**
     * Find all notifications by user ID and status
     * 
     * @param userId - The user ID
     * @param status - The notification status
     * @return List of notifications
     */
    List<Notification> findByUserIdAndStatusOrderByCreatedAtDesc(String userId, NotificationStatus status);

    /**
     * Count notifications by user ID and status
     * 
     * @param userId - The user ID
     * @param status - The notification status
     * @return Count of notifications
     */
    int countByUserIdAndStatus(String userId, NotificationStatus status);

    /**
     * Mark multiple notifications as read
     * 
     * @param ids    - List of notification IDs to update
     * @param readAt - Timestamp when notifications were read
     * @return Number of updated records
     */
    @Modifying
    @Query("UPDATE Notification n SET n.status = 'READ', n.readAt = :readAt WHERE n.id IN :ids")
    int markNotificationsAsRead(@Param("ids") List<String> ids, @Param("readAt") LocalDateTime readAt);

    /**
     * Mark multiple notifications as unread
     * 
     * @param ids - List of notification IDs to update
     * @return Number of updated records
     */
    @Modifying
    @Query("UPDATE Notification n SET n.status = 'UNREAD', n.readAt = null WHERE n.id IN :ids")
    int markNotificationsAsUnread(@Param("ids") List<String> ids);

    /**
     * Mark all notifications for a user as read
     * 
     * @param userId - The user ID
     * @param readAt - Timestamp when notifications were read
     * @return Number of updated records
     */
    @Modifying
    @Query("UPDATE Notification n SET n.status = 'READ', n.readAt = :readAt WHERE n.user.id = :userId AND n.status = 'UNREAD'")
    int markAllNotificationsAsRead(@Param("userId") String userId, @Param("readAt") LocalDateTime readAt);

    /**
     * Delete expired notifications based on their priority and creation date
     * 
     * @param lowPriorityCutoff    - Cutoff date for low priority notifications (30 days)
     * @param mediumPriorityCutoff - Cutoff date for medium priority notifications (60 days)
     * @param highPriorityCutoff   - Cutoff date for high priority notifications (90 days)
     * @return Number of deleted records
     */
    @Modifying
    @Query("DELETE FROM Notification n WHERE (n.priority = 'LOW' AND n.createdAt < :lowPriorityCutoff) OR "
            + "(n.priority = 'MEDIUM' AND n.createdAt < :mediumPriorityCutoff) OR "
            + "(n.priority = 'HIGH' AND n.createdAt < :highPriorityCutoff)")
    int deleteExpiredNotifications(@Param("lowPriorityCutoff") LocalDateTime lowPriorityCutoff,
            @Param("mediumPriorityCutoff") LocalDateTime mediumPriorityCutoff,
            @Param("highPriorityCutoff") LocalDateTime highPriorityCutoff);
}