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
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.utils.ResponseEntityBuilder;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final Logger logger = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    private AuditLogService auditLogService;

    /**
     * Endpoint to trigger audit log cleanup
     * 
     * @param months Number of months to retain logs (default: 3)
     * @return Response with deletion count
     */
    @DeleteMapping("/audit-logs/cleanup")
    @PreAuthorize("hasRole('ADMIN')") // Now this will work with @EnableMethodSecurity
    public ResponseEntityDTO<Integer> cleanupAuditLogs(@RequestParam(required = false) Integer months) {
        try {
            int deletedCount;
            if (months != null && months > 0) {
                LocalDateTime cutoffDate = LocalDateTime.now().minusMonths(months);
                deletedCount = auditLogService.deleteOldAuditLogs(cutoffDate);
            } else {
                deletedCount = auditLogService.deleteOldAuditLogs();
            }
            return new ResponseEntityBuilder<Integer>().setData(deletedCount)
                    .setMessage("Successfully deleted " + deletedCount + " audit logs").build();
        } catch (Exception e) {
            logger.error("Error cleaning up audit logs: {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to clean up audit logs");
        }
    }
}