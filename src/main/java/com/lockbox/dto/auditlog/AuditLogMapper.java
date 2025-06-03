package com.lockbox.dto.auditlog;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import com.lockbox.model.AuditLog;
import com.lockbox.model.User;

/**
 * Mapper class for converting between {@link AuditLog} entities and DTOs.
 */
@Component
public class AuditLogMapper {

    /**
     * Convert an {@link AuditLog} entity to an {@link AuditLogDTO}
     * 
     * @param auditLog - The AuditLog entity
     * @return {@link AuditLogDTO} representation of the audit log
     */
    public AuditLogDTO toDTO(AuditLog auditLog) {
        if (auditLog == null) {
            return null;
        }

        AuditLogDTO dto = new AuditLogDTO();
        dto.setId(auditLog.getId());
        dto.setUserId(auditLog.getUser() != null ? auditLog.getUser().getId() : null);
        dto.setUsername(auditLog.getUser() != null ? auditLog.getUser().getUsername() : null);
        dto.setActionType(auditLog.getActionType());
        dto.setResourceId(auditLog.getResourceId());
        dto.setResourceName(auditLog.getResourceName());
        dto.setClientInfo(auditLog.getClientInfo());
        dto.setIpAddress(auditLog.getIpAddress());
        dto.setActionStatus(auditLog.getActionStatus());
        dto.setFailureReason(auditLog.getFailureReason());
        dto.setAdditionalInfo(auditLog.getAdditionalInfo());
        dto.setTimestamp(auditLog.getTimestamp());

        return dto;
    }

    /**
     * Convert a list of {@link AuditLog} entities to a list of {@link AuditLogDTO}s
     * 
     * @param auditLogs - The list of AuditLog entities
     * @return List of {@link AuditLogDTO}s
     */
    public List<AuditLogDTO> toDTOList(List<AuditLog> auditLogs) {
        if (auditLogs == null) {
            return null;
        }

        return auditLogs.stream().map(this::toDTO).collect(Collectors.toList());
    }

    /**
     * Convert an {@link AuditLogDTO} to an {@link AuditLog} entity
     * 
     * @param dto  - The AuditLogDTO
     * @param user - The {@link User} entity
     * @return {@link AuditLog} entity
     */
    public AuditLog toEntity(AuditLogDTO dto, User user) {
        if (dto == null) {
            return null;
        }

        AuditLog auditLog = new AuditLog();
        auditLog.setUser(user);
        auditLog.setActionType(dto.getActionType());
        auditLog.setResourceId(dto.getResourceId());
        auditLog.setResourceName(dto.getResourceName());
        auditLog.setClientInfo(dto.getClientInfo());
        auditLog.setIpAddress(dto.getIpAddress());
        auditLog.setActionStatus(dto.getActionStatus());
        auditLog.setFailureReason(dto.getFailureReason());
        auditLog.setAdditionalInfo(dto.getAdditionalInfo());
        auditLog.setTimestamp(dto.getTimestamp() != null ? dto.getTimestamp() : LocalDateTime.now());

        return auditLog;
    }
}