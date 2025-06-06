package com.lockbox.service.auditlog;

import java.time.LocalDateTime;

import com.lockbox.dto.auditlog.AuditLogDTO;
import com.lockbox.dto.auditlog.AuditLogListResponseDTO;
import com.lockbox.dto.auditlog.AuditLogResponseDTO;
import com.lockbox.model.ActionType;
import com.lockbox.model.LogLevel;
import com.lockbox.model.OperationType;

public interface AuditLogService {

    AuditLogListResponseDTO findAllAuditLogsByUser(String userId, Integer page, Integer size) throws Exception;

    AuditLogListResponseDTO findAuditLogsByUserAndType(String userId, String actionType, Integer page, Integer size)
            throws Exception;

    AuditLogListResponseDTO findAuditLogsByUserAndFilters(String userId, OperationType operationType, LogLevel logLevel,
            LocalDateTime startDate, LocalDateTime endDate, Integer page, Integer size) throws Exception;

    AuditLogListResponseDTO findAuditLogsByUserAndDateRange(String userId, LocalDateTime startDate,
            LocalDateTime endDate, Integer page, Integer size) throws Exception;

    AuditLogResponseDTO createAuditLog(AuditLogDTO auditLogDTO, String userId) throws Exception;

    AuditLogResponseDTO logUserAction(String userId, ActionType actionType, OperationType operationType,
            LogLevel logLevel, String resourceId, String resourceName, String status, String failureReason,
            String additionalInfo) throws Exception;

    AuditLogListResponseDTO getFilteredAuditLogs(String userId, Integer page, Integer size, String operationType,
            String level, String startDateStr, String endDateStr) throws Exception;

    int deleteOldAuditLogs(LocalDateTime cutoffDate) throws Exception;

    int deleteOldAuditLogs() throws Exception;
}