package com.lockbox.scheduler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.SchedulerMessages;

@Component
public class AuditLogCleanupScheduler {

    private final Logger logger = LoggerFactory.getLogger(AuditLogCleanupScheduler.class);

    @Autowired
    private AuditLogService auditLogService;

    /**
     * Scheduled task to delete old audit logs.
     * 
     * Runs at 2:00 AM every Sunday.
     */
    @Scheduled(cron = AppConstants.SchedulerIntervals.AUDIT_LOG_CLEANUP_CRON)
    public void cleanupOldAuditLogs() {
        try {
            logger.info(SchedulerMessages.AUDIT_LOG_CLEANUP_START);
            int deletedCount = auditLogService.deleteOldAuditLogs();
            logger.info(SchedulerMessages.AUDIT_LOG_CLEANUP_COMPLETE, deletedCount);
        } catch (Exception e) {
            logger.error(SchedulerMessages.AUDIT_LOG_CLEANUP_ERROR, e.getMessage(), e);
        }
    }
}