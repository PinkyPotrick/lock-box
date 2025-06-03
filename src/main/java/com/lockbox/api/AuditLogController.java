package com.lockbox.api;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.lockbox.dto.ResponseEntityDTO;
import com.lockbox.dto.auditlog.AuditLogListResponseDTO;
import com.lockbox.service.auditlog.AuditLogService;
import com.lockbox.utils.ResponseEntityBuilder;
import com.lockbox.utils.SecurityUtils;

@RestController
@RequestMapping("/api/audit-logs")
public class AuditLogController {

    @Autowired
    private AuditLogService auditLogService;

    @Autowired
    private SecurityUtils securityUtils;

    @GetMapping
    public ResponseEntityDTO<AuditLogListResponseDTO> getAuditLogs(
            @RequestParam(name = "page", required = false) Integer page,
            @RequestParam(name = "size", required = false) Integer size,
            @RequestParam(name = "actionType", required = false) String actionType,
            @RequestParam(name = "startDate", required = false) String startDateStr,
            @RequestParam(name = "endDate", required = false) String endDateStr) {
        try {
            String userId = securityUtils.getCurrentUserId();
            AuditLogListResponseDTO response;

            // Handle different filter scenarios
            if (actionType != null) {
                response = auditLogService.findAuditLogsByUserAndType(userId, actionType, page, size);
            } else if (startDateStr != null && endDateStr != null) {
                DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
                LocalDateTime startDate = LocalDateTime.parse(startDateStr, formatter);
                LocalDateTime endDate = LocalDateTime.parse(endDateStr, formatter);
                response = auditLogService.findAuditLogsByUserAndDateRange(userId, startDate, endDate, page, size);
            } else {
                response = auditLogService.findAllAuditLogsByUser(userId, page, size);
            }

            return new ResponseEntityBuilder<AuditLogListResponseDTO>().setData(response)
                    .setMessage("Audit logs retrieved successfully").build();
        } catch (Exception e) {
            return ResponseEntityBuilder.handleErrorDTO(e, "Failed to fetch audit logs");
        }
    }
}