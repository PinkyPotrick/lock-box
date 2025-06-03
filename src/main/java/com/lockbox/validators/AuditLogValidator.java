package com.lockbox.validators;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

import org.springframework.stereotype.Component;

import com.lockbox.dto.auditlog.AuditLogDTO;
import com.lockbox.exception.ValidationException;
import com.lockbox.model.AuditLog.LogLevel;
import com.lockbox.model.AuditLog.OperationType;
import com.lockbox.utils.AppConstants;
import com.lockbox.utils.AppConstants.FieldNames;
import com.lockbox.utils.AppConstants.MaxLengths;
import com.lockbox.utils.AppConstants.ValidationErrors;

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
            validateMaxLength(auditLogDTO.getActionType(), MaxLengths.ACTION_TYPE, FieldNames.ACTION_TYPE);
        }

        if (hasContent(auditLogDTO.getResourceId())) {
            validateMaxLength(auditLogDTO.getResourceId(), MaxLengths.RESOURCE_ID, FieldNames.RESOURCE_ID);
        }

        if (hasContent(auditLogDTO.getResourceName())) {
            validateMaxLength(auditLogDTO.getResourceName(), MaxLengths.RESOURCE_NAME, FieldNames.RESOURCE_NAME);
        }

        if (hasContent(auditLogDTO.getClientInfo())) {
            validateMaxLength(auditLogDTO.getClientInfo(), MaxLengths.CLIENT_INFO, FieldNames.CLIENT_INFO);
        }

        if (hasContent(auditLogDTO.getIpAddress())) {
            validateMaxLength(auditLogDTO.getIpAddress(), MaxLengths.IP_ADDRESS, FieldNames.IP_ADDRESS);
        }

        if (hasContent(auditLogDTO.getFailureReason())) {
            validateMaxLength(auditLogDTO.getFailureReason(), MaxLengths.FAILURE_REASON, FieldNames.FAILURE_REASON);
        }

        if (hasContent(auditLogDTO.getAdditionalInfo())) {
            validateMaxLength(auditLogDTO.getAdditionalInfo(), MaxLengths.ADDITIONAL_INFO, FieldNames.ADDITIONAL_INFO);
        }
    }

    /**
     * Validate audit log filter parameters
     * 
     * @param operationType Operation type string to validate
     * @param level         Log level string to validate
     * @param startDateStr  Start date string to validate
     * @param endDateStr    End date string to validate
     * @throws ValidationException If validation fails
     */
    public void validateFilterParameters(String operationType, String level, String startDateStr, String endDateStr)
            throws ValidationException {

        // Validate operation type if provided
        if (hasContent(operationType) && !operationType.equalsIgnoreCase("ALL")) {
            try {
                OperationType.valueOf(operationType.toUpperCase());
            } catch (IllegalArgumentException e) {
                throwValidationException(ValidationErrors.INVALID_OPERATION_TYPE);
            }
        }

        // Validate log level if provided
        if (hasContent(level) && !level.equalsIgnoreCase("ALL")) {
            try {
                LogLevel.valueOf(level.toUpperCase());
            } catch (IllegalArgumentException e) {
                throwValidationException(ValidationErrors.INVALID_LOG_LEVEL);
            }
        }

        // Validate date format
        if (hasContent(startDateStr)) {
            try {
                LocalDateTime.parse(startDateStr, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            } catch (DateTimeParseException e) {
                throwValidationException(ValidationErrors.INVALID_DATE_FORMAT);
            }
        }

        if (hasContent(endDateStr)) {
            try {
                LocalDateTime.parse(endDateStr, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            } catch (DateTimeParseException e) {
                throwValidationException(ValidationErrors.INVALID_DATE_FORMAT);
            }
        }

        // Validate date range logic
        if (hasContent(startDateStr) && hasContent(endDateStr)) {
            LocalDateTime startDate = LocalDateTime.parse(startDateStr, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            LocalDateTime endDate = LocalDateTime.parse(endDateStr, DateTimeFormatter.ISO_LOCAL_DATE_TIME);

            if (startDate.isAfter(endDate)) {
                throwValidationException(ValidationErrors.INVALID_DATE_RANGE);
            }
        }
    }
}