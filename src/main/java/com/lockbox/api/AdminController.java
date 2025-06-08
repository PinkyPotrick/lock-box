package com.lockbox.api;

import java.time.LocalDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.model.enums.ActionType;
import com.lockbox.model.enums.LogLevel;
import com.lockbox.model.enums.OperationType;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.service.notification.NotificationService;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.ActionStatus;
import com.lockbox.utils.AppConstants.AuditLogMessages;
import com.lockbox.utils.AppConstants.LogMessages;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final Logger logger = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private NotificationService notificationService;

    @Autowired
    private SecurityUtils securityUtils;

    // curl -X DELETE "http://localhost:8080/api/admin/audit-logs/cleanup" -H "Authorization: Basic $(echo -n user:pass
    // | base64)"
    // curl -v -X DELETE "http://localhost:8080/api/admin/audit-logs/cleanup" -H "Authorization: Basic $(echo -n
    // user:pass | base64)"

    @DeleteMapping("/audit-logs/cleanup")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntityDTO<Integer> cleanupAuditLogs(@RequestParam(required = false) Integer months) {
        try {
            String userId = securityUtils.getCurrentUserId();
            int deletedCount;
            if (months != null && months > 0) {
                LocalDateTime cutoffDate = LocalDateTime.now().minus(months, AppConstants.AUDIT_LOG_RETENTION_UNIT);
                deletedCount = auditLogService.deleteOldAuditLogs(cutoffDate);
            } else {
                deletedCount = auditLogService.deleteOldAuditLogs();
            }

            // Log the admin action
            try {
                auditLogService.logUserAction(userId, ActionType.ADMIN_AUDIT_LOG_CLEANUP, OperationType.DELETE,
                        LogLevel.INFO, null, "Audit Log System", ActionStatus.SUCCESS, null,
                        String.format(AuditLogMessages.ADMIN_CLEANED_AUDIT_LOGS, deletedCount,
                                (months != null ? months + " months" : "default")));
            } catch (Exception e) {
                logger.error(LogMessages.AUDIT_LOG_FAILED, e.getMessage());
            }

            return new ResponseEntityBuilder<Integer>().setData(deletedCount)
                    .setMessage("Successfully deleted " + deletedCount + " audit logs").build();
        } catch (Exception e) {
            logger.error("Error cleaning up audit logs: {}", e.getMessage(), e);

            try {
                // Get current user from security context
                String userId = securityUtils.getCurrentUserId();

                // Log the failure
                auditLogService.logUserAction(userId, ActionType.ADMIN_AUDIT_LOG_CLEANUP, OperationType.DELETE,
                        LogLevel.ERROR, null, "Audit Log System", ActionStatus.FAILURE, e.getMessage(),
                        AuditLogMessages.FAILED_CLEANUP);
            } catch (Exception ex) {
                logger.error(LogMessages.AUDIT_LOG_FAILED, ex.getMessage());
            }

            return ResponseEntityBuilder.handleErrorDTO(e, AuditLogMessages.FAILED_CLEANUP);
        }
    }

    @DeleteMapping("/notifications/cleanup")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntityDTO<Integer> cleanupExpiredNotifications() {
        try {
            int deletedCount = notificationService.cleanupExpiredNotifications();

            return new ResponseEntityBuilder<Integer>().setData(deletedCount)
                    .setMessage("Successfully deleted " + deletedCount + " expired notifications").build();
        } catch (Exception e) {
            logger.error("Error cleaning up expired notifications: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to clean up expired notifications");
        }
    }
}