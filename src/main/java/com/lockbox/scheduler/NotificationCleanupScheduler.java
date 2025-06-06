package com.lockbox.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.lockbox.service.notification.NotificationService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.SchedulerMessages;

@Component
public class NotificationCleanupScheduler {

    private final Logger logger = LoggerFactory.getLogger(NotificationCleanupScheduler.class);

    @Autowired
    private NotificationService notificationService;

    /**
     * Scheduled task to clean up expired notifications based on their priority. Low priority: 30 days, Medium priority:
     * 60 days, High priority: 90 days. Critical priority notifications are not auto-expired.
     * 
     * Runs at 3:00 AM every day.
     */
    @Scheduled(cron = AppConstants.SchedulerIntervals.NOTIFICATION_CLEANUP_CRON)
    public void cleanupExpiredNotifications() {
        try {
            logger.info(SchedulerMessages.NOTIFICATION_CLEANUP_START);
            int deletedCount = notificationService.cleanupExpiredNotifications();
            logger.info(SchedulerMessages.NOTIFICATION_LOG_CLEANUP_COMPLETE, deletedCount);
        } catch (Exception e) {
            logger.error(SchedulerMessages.NOTIFICATION_LOG_CLEANUP_ERROR, e.getMessage(), e);
        }
    }
}