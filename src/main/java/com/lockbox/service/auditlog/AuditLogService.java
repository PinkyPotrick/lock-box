package com.lockbox.service.auditlog;

import java.time.LocalDateTime;

import com.lockbox.dto.auditlog.AuditLogDTO;
import com.lockbox.dto.auditlog.AuditLogListResponseDTO;
import com.lockbox.dto.auditlog.AuditLogResponseDTO;

public interface AuditLogService {

    AuditLogListResponseDTO findAllAuditLogsByUser(String userId, Integer page, Integer size) throws Exception;

    AuditLogListResponseDTO findAuditLogsByUserAndType(String userId, String actionType, Integer page, Integer size)
            throws Exception;

    AuditLogListResponseDTO findAuditLogsByUserAndDateRange(String userId, LocalDateTime startDate,
            LocalDateTime endDate, Integer page, Integer size) throws Exception;

    AuditLogResponseDTO createAuditLog(AuditLogDTO auditLogDTO, String userId) throws Exception;

    void deleteOldAuditLogs(LocalDateTime cutoffDate) throws Exception;
}