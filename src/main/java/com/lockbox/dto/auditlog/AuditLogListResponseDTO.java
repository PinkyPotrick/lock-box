package com.lockbox.dto.auditlog;

import java.util.List;

public class AuditLogListResponseDTO {

    private List<AuditLogResponseDTO> auditLogs;
    private int totalCount;

    public AuditLogListResponseDTO() {
    }

    public AuditLogListResponseDTO(List<AuditLogResponseDTO> auditLogs, int totalCount) {
        this.auditLogs = auditLogs;
        this.totalCount = totalCount;
    }

    public List<AuditLogResponseDTO> getAuditLogs() {
        return auditLogs;
    }

    public void setAuditLogs(List<AuditLogResponseDTO> auditLogs) {
        this.auditLogs = auditLogs;
    }

    public int getTotalCount() {
        return totalCount;
    }

    public void setTotalCount(int totalCount) {
        this.totalCount = totalCount;
    }
}