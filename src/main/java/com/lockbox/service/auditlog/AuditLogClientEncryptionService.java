package com.lockbox.service.auditlog;

import java.util.List;

import com.lockbox.dto.auditlog.AuditLogDTO;
import com.lockbox.dto.auditlog.AuditLogListResponseDTO;
import com.lockbox.dto.auditlog.AuditLogRequestDTO;
import com.lockbox.dto.auditlog.AuditLogResponseDTO;

public interface AuditLogClientEncryptionService {

    AuditLogResponseDTO encryptAuditLogForClient(AuditLogDTO auditLogDTO) throws Exception;

    AuditLogListResponseDTO encryptAuditLogListForClient(List<AuditLogDTO> auditLogDTOs) throws Exception;

    AuditLogDTO decryptAuditLogFromClient(AuditLogRequestDTO requestDTO) throws Exception;
}