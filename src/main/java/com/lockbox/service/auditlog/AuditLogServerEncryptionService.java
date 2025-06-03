package com.lockbox.service.auditlog;

import com.lockbox.model.AuditLog;

public interface AuditLogServerEncryptionService {

    AuditLog encryptServerData(AuditLog auditLog) throws Exception;

    AuditLog decryptServerData(AuditLog auditLog) throws Exception;
}