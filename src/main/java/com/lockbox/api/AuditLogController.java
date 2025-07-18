package com.lockbox.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.auditlog.AuditLogListResponseDTO;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.utils.AppConstants.Errors;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/audit-logs")
public class AuditLogController {

    private final Logger logger = LoggerFactory.getLogger(AuditLogController.class);

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntityDTO<AuditLogListResponseDTO> getAuditLogs(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "operationType", required = false) String operationType,
            @RequestParam(name = "level", required = false) String level,
            @RequestParam(name = "startDate", required = false) String startDate,
            @RequestParam(name = "endDate", required = false) String endDate) {

        try {
            String userId = securityUtils.getCurrentUserId();
            AuditLogListResponseDTO response = auditLogService.getFilteredAuditLogs(userId, page, size, operationType,
                    level, startDate, endDate);

            return new ResponseEntityBuilder<AuditLogListResponseDTO>().setData(response)
                    .setMessage("Audit logs retrieved successfully").build();
        } catch (Exception e) {
            logger.error(Errors.FETCH_AUDIT_LOGS_FAILED + ": {}", e.getMessage(), e);
            return ResponseEntityBuilder.handleErrorDTO(e, Errors.FETCH_AUDIT_LOGS_FAILED);
        }
    }
}