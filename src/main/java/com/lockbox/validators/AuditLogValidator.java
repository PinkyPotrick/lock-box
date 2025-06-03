package com.lockbox.validators;

import org.springframework.stereotype.Component;

import com.lockbox.dto.auditlog.AuditLogDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.FieldNames;
import com.lockbox.utils.AppConstants.MaxLengths;

/**
 * Validator for audit log-related DTOs.
 */
@Component
public class AuditLogValidator extends BaseValidator {

    /**
     * Creates a new audit log validator.
     */
    public AuditLogValidator() {
        super(AppConstants.EntityTypes.AUDIT_LOG);
    }

    /**
     * Validate an audit log DTO
     * 
     * @param auditLogDTO - The audit log DTO to validate
     * @throws ValidationException If validation fails
     */
    public void validateAuditLogDTO(AuditLogDTO auditLogDTO) throws ValidationException {
        validateNotNull(auditLogDTO, FieldNames.AUDIT_LOG_DATA);
        validateRequired(auditLogDTO.getActionType(), FieldNames.ACTION_TYPE, "Action type is required");
        validateRequired(auditLogDTO.getActionStatus(), FieldNames.ACTION_STATUS, "Action status is required");

        if (hasContent(auditLogDTO.getActionType())) {
            validateMaxLength(auditLogDTO.getActionType(), 50, FieldNames.ACTION_TYPE);
        }

        if (hasContent(auditLogDTO.getResourceId())) {
            validateMaxLength(auditLogDTO.getResourceId(), 255, FieldNames.RESOURCE_ID);
        }

        if (hasContent(auditLogDTO.getResourceName())) {
            validateMaxLength(auditLogDTO.getResourceName(), MaxLengths.NAME, FieldNames.RESOURCE_NAME);
        }

        if (hasContent(auditLogDTO.getClientInfo())) {
            validateMaxLength(auditLogDTO.getClientInfo(), 255, FieldNames.CLIENT_INFO);
        }

        if (hasContent(auditLogDTO.getIpAddress())) {
            validateMaxLength(auditLogDTO.getIpAddress(), 50, FieldNames.IP_ADDRESS);
        }

        if (hasContent(auditLogDTO.getFailureReason())) {
            validateMaxLength(auditLogDTO.getFailureReason(), 1024, FieldNames.FAILURE_REASON);
        }

        if (hasContent(auditLogDTO.getAdditionalInfo())) {
            validateMaxLength(auditLogDTO.getAdditionalInfo(), 2048, FieldNames.ADDITIONAL_INFO);
        }
    }
}